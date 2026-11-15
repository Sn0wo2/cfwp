use worker::{Error, Result, Socket};

use crate::dns::DnsService;

pub(super) async fn connect_tcp(dns: &DnsService, hostname: &str, port: u16) -> Result<Socket> {
    Socket::builder().connect(
        dns.resolve(hostname)
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| Error::RustError("DNS returned no usable addresses".into()))?
            .to_string(),
        port,
    )
}

pub(super) async fn resolve_candidates(
    hostname: &str,
    port: u16,
    dns: &DnsService,
    candidates: &mut Vec<(String, u16)>,
    limit: usize,
) {
    if candidates.len() >= limit {
        return;
    }
    if let Ok(addresses) = dns.resolve(hostname).await {
        for address in addresses {
            let candidate = (address.to_string(), port);
            if !candidates.contains(&candidate) {
                candidates.push(candidate);
                if candidates.len() == limit {
                    break;
                }
            }
        }
    }
}
