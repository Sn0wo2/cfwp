use std::net::IpAddr;

use worker::{Error, Result, Socket};

use crate::config::parse_tproxy_servers;
use crate::dns::DnsService;

use super::utils::{connect_tcp, resolve_candidates};

pub(super) async fn connect(
    addresses: &[(String, u16)],
    payload: &[u8],
    dns: &DnsService,
) -> Result<Socket> {
    let mut candidates = Vec::new();
    let mut fallbacks = Vec::new();
    for (host, port) in addresses {
        if candidates.len() == 16 {
            break;
        }
        if host.parse::<IpAddr>().is_ok() {
            if !fallbacks.iter().any(|(candidate_host, candidate_port)| {
                candidate_host == host && candidate_port == port
            }) {
                fallbacks.push((host.clone(), *port));
            }
            continue;
        }

        if let Ok(records) = dns.resolve_txt(host).await {
            for record in records {
                if candidates.len() == 16 {
                    break;
                }
                let Ok(targets) = parse_tproxy_servers(&record, *port) else {
                    continue;
                };
                for (host, port) in targets {
                    if candidates.len() == 16 {
                        break;
                    }
                    resolve_candidates(&host, port, dns, &mut candidates, 16).await;
                }
            }
        }
        if candidates.len() == 16 {
            break;
        }
        resolve_candidates(host, *port, dns, &mut fallbacks, 16).await;
    }

    for fallback in fallbacks {
        if candidates.len() == 16 {
            break;
        }
        if !candidates.contains(&fallback) {
            candidates.push(fallback);
        }
    }
    let mut last_error = None;
    for (host, port) in candidates {
        match match connect_tcp(dns, &host, port).await {
            Ok(socket) => super::super::util::open_and_send(socket, payload, "tproxy").await,
            Err(err) => Err(err),
        } {
            Ok(socket) => return Ok(socket),
            Err(err) => last_error = Some(err),
        }
    }
    Err(last_error
        .unwrap_or_else(|| Error::RustError("tproxy has no usable server candidates".into())))
}
