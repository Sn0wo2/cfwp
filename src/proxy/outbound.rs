use std::net::IpAddr;

use base64::Engine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use worker::{Error, Result, Socket};

use super::protocol::InitialRequest;
use super::util::CONNECT_TIMEOUT_MS;
use crate::config::{Config, OutboundConfig, parse_tproxy_servers};
use crate::dns::DnsService;
use crate::util::with_timeout;

const MAX_PROXY_CANDIDATES: usize = 16;

pub(super) async fn connect_tcp(dns: &DnsService, hostname: &str, port: u16) -> Result<Socket> {
    let address = dns
        .resolve(hostname)
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| Error::RustError("DNS returned no usable addresses".into()))?;
    Socket::builder().connect(address.to_string(), port)
}

#[derive(Clone)]
pub(super) struct ProxyPlan {
    outbound: ProxyEntry,
}

#[derive(Clone)]
enum ProxyEntry {
    Direct,
    Tproxy(Vec<ProxyAddress>),
    Socks4(ProxyCredential),
    Socks5(ProxyCredential),
    Http(ProxyCredential),
}

#[derive(Clone, PartialEq, Eq)]
struct ProxyAddress {
    host: String,
    port: u16,
}

#[derive(Clone)]
struct ProxyCredential {
    host: String,
    port: u16,
    username: Option<String>,
    password: Option<String>,
}

impl ProxyPlan {
    #[allow(clippy::single_call_fn, clippy::literal_string_with_formatting_args)]
    pub(super) fn from_config(config: &Config, colo: Option<&str>) -> Result<Self> {
        let outbound = match config
            .final_outbound()
            .ok_or_else(|| Error::RustError("route.final references an unknown outbound".into()))?
        {
            OutboundConfig::Direct(_) => ProxyEntry::Direct,
            OutboundConfig::Socks(config) => {
                let credential = ProxyCredential {
                    host: config.server.clone(),
                    port: config.server_port,
                    username: config.username.clone(),
                    password: config.password.clone(),
                };
                match config.version.as_str() {
                    "4" => ProxyEntry::Socks4(credential),
                    "5" => ProxyEntry::Socks5(credential),
                    _ => return Err(Error::RustError("unsupported SOCKS version".into())),
                }
            }
            OutboundConfig::Http(config) => ProxyEntry::Http(ProxyCredential {
                host: config.server.clone(),
                port: config.server_port,
                username: config.username.clone(),
                password: config.password.clone(),
            }),
            OutboundConfig::Tproxy(config) => {
                let servers = config
                    .server
                    .split(',')
                    .filter_map(|server| {
                        if server.contains("{colo}") {
                            colo.map(|colo| server.replace("{colo}", colo))
                        } else {
                            Some(server.to_string())
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(",");
                ProxyEntry::Tproxy(if servers.is_empty() {
                    Vec::new()
                } else {
                    parse_tproxy_servers(&servers, config.server_port)?
                        .into_iter()
                        .map(|(host, port)| ProxyAddress { host, port })
                        .collect()
                })
            }
        };
        Ok(Self { outbound })
    }

    pub(super) async fn connect(
        &self,
        target: &InitialRequest,
        dns: &DnsService,
    ) -> Result<Socket> {
        self.connect_to(&target.hostname, target.port, &target.payload, dns)
            .await
    }

    #[allow(clippy::single_call_fn)]
    pub(super) async fn connect_address(
        &self,
        hostname: &str,
        port: u16,
        dns: &DnsService,
    ) -> Result<Socket> {
        self.connect_to(hostname, port, &[], dns).await
    }

    async fn connect_to(
        &self,
        hostname: &str,
        port: u16,
        payload: &[u8],
        dns: &DnsService,
    ) -> Result<Socket> {
        match &self.outbound {
            ProxyEntry::Direct => {
                let mut socket = connect_tcp(dns, hostname, port).await?;
                match with_timeout(CONNECT_TIMEOUT_MS, async {
                    socket.opened().await?;
                    if !payload.is_empty() {
                        socket.write_all(payload).await?;
                        socket.flush().await?;
                    }
                    Ok(())
                })
                .await
                {
                    Some(Ok(())) => Ok(socket),
                    Some(Err(err)) => {
                        drop(socket.close().await);
                        Err(err)
                    }
                    None => {
                        drop(socket.close().await);
                        Err(Error::RustError(format!(
                            "target connection timed out after {CONNECT_TIMEOUT_MS} ms"
                        )))
                    }
                }
            }
            ProxyEntry::Tproxy(addresses) => {
                let candidates = resolve_tproxy_candidates(addresses, dns).await;
                let mut last_error = None;
                for address in &candidates {
                    match connect_tproxy_address(address, payload, dns).await {
                        Ok(socket) => return Ok(socket),
                        Err(err) => last_error = Some(err),
                    }
                }
                Err(last_error.unwrap_or_else(|| {
                    Error::RustError("tproxy has no usable server candidates".into())
                }))
            }
            ProxyEntry::Socks4(proxy) | ProxyEntry::Socks5(proxy) | ProxyEntry::Http(proxy) => {
                self.connect_via_proxy(proxy, hostname, port, payload, dns)
                    .await
            }
        }
    }

    pub(super) const fn kind_name(&self) -> &'static str {
        match &self.outbound {
            ProxyEntry::Direct => "direct",
            ProxyEntry::Tproxy(_) => "tproxy",
            ProxyEntry::Socks4(_) => "socks4",
            ProxyEntry::Socks5(_) => "socks5",
            ProxyEntry::Http(_) => "http",
        }
    }

    async fn connect_via_proxy(
        &self,
        proxy: &ProxyCredential,
        hostname: &str,
        port: u16,
        payload: &[u8],
        dns: &DnsService,
    ) -> Result<Socket> {
        let target_address = dns
            .resolve(hostname)
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| Error::RustError("DNS returned no usable addresses".into()))?;
        let mut socket = connect_tcp(dns, &proxy.host, proxy.port).await?;
        match with_timeout(CONNECT_TIMEOUT_MS, async {
            socket.opened().await?;
            match &self.outbound {
                ProxyEntry::Socks5(_) => {
                    socket
                        .write_all(if proxy.username.is_some() && proxy.password.is_some() {
                            &[0x05, 0x02, 0x00, 0x02]
                        } else {
                            &[0x05, 0x01, 0x00]
                        })
                        .await?;

                    let mut response = [0_u8; 2];
                    socket.read_exact(&mut response).await?;
                    if response[0] != 0x05 {
                        return Err(Error::RustError("invalid tunnel version".into()));
                    }
                    if response[1] == 0x02 {
                        let username = proxy.username.as_deref().unwrap_or_default().as_bytes();
                        let password = proxy.password.as_deref().unwrap_or_default().as_bytes();
                        if username.len() > u8::MAX as usize || password.len() > u8::MAX as usize {
                            return Err(Error::RustError("credential payload too long".into()));
                        }
                        let mut auth = Vec::with_capacity(3 + username.len() + password.len());
                        auth.push(0x01);
                        auth.push(username.len() as u8);
                        auth.extend_from_slice(username);
                        auth.push(password.len() as u8);
                        auth.extend_from_slice(password);
                        socket.write_all(&auth).await?;
                        socket.read_exact(&mut response).await?;
                        if response[1] != 0x00 {
                            return Err(Error::RustError("credential check failed".into()));
                        }
                    } else if response[1] != 0x00 {
                        return Err(Error::RustError("unsupported credential mode".into()));
                    }

                    let mut connect_request = vec![0x05, 0x01, 0x00];
                    match target_address {
                        IpAddr::V4(ipv4) => {
                            connect_request.push(0x01);
                            connect_request.extend_from_slice(&ipv4.octets());
                        }
                        IpAddr::V6(ipv6) => {
                            connect_request.push(0x04);
                            connect_request.extend_from_slice(&ipv6.octets());
                        }
                    }
                    connect_request.extend_from_slice(&port.to_be_bytes());
                    socket.write_all(&connect_request).await?;

                    let mut header = [0_u8; 4];
                    socket.read_exact(&mut header).await?;
                    if header[1] != 0x00 {
                        return Err(Error::RustError(format!(
                            "route setup failed: {}",
                            header[1]
                        )));
                    }

                    let address_len = match header[3] {
                        0x01 => 4,
                        0x03 => {
                            let mut len = [0_u8; 1];
                            socket.read_exact(&mut len).await?;
                            len[0] as usize
                        }
                        0x04 => 16,
                        _ => return Err(Error::RustError("invalid bind address".into())),
                    };
                    socket
                        .read_exact(&mut vec![0_u8; address_len + 2])
                        .await?;
                    if !payload.is_empty() {
                        socket.write_all(payload).await?;
                        socket.flush().await?;
                    }
                }
                ProxyEntry::Socks4(_) => {
                    let IpAddr::V4(ipv4) = target_address else {
                        return Err(Error::RustError(
                            "SOCKS4 requires an IPv4 target".into(),
                        ));
                    };
                    let username = proxy.username.as_deref().unwrap_or_default();
                    let mut request = Vec::with_capacity(9 + username.len());
                    request.extend_from_slice(&[0x04, 0x01]);
                    request.extend_from_slice(&port.to_be_bytes());
                    request.extend_from_slice(&ipv4.octets());
                    request.extend_from_slice(username.as_bytes());
                    request.push(0);
                    socket.write_all(&request).await?;

                    let mut response = [0_u8; 8];
                    socket.read_exact(&mut response).await?;
                    if response[1] != 0x5a {
                        return Err(Error::RustError(format!(
                            "SOCKS4 route setup failed: {}",
                            response[1]
                        )));
                    }
                    if !payload.is_empty() {
                        socket.write_all(payload).await?;
                        socket.flush().await?;
                    }
                }
                ProxyEntry::Http(_) => {
                    let authority = if target_address.is_ipv6() {
                        format!("[{target_address}]:{port}")
                    } else {
                        format!("{target_address}:{port}")
                    };
                    let mut request = format!(
                        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: cfwp\r\nProxy-Connection: Keep-Alive\r\n"
                    );
                    if let (Some(username), Some(password)) = (&proxy.username, &proxy.password) {
                        request.push_str(&format!(
                            "Proxy-Authorization: Basic {}\r\n",
                            base64::engine::general_purpose::STANDARD
                                .encode(format!("{username}:{password}"))
                        ));
                    }
                    request.push_str("\r\n");
                    socket.write_all(request.as_bytes()).await?;

                    let mut response = Vec::new();
                    let mut byte = [0_u8; 1];
                    while response.len() < 8192 {
                        let read = socket.read(&mut byte).await?;
                        if read == 0 {
                            break;
                        }
                        response.push(byte[0]);
                        if response.ends_with(b"\r\n\r\n") {
                            break;
                        }
                    }
                    let mut headers = [httparse::EMPTY_HEADER; 64];
                    let mut parsed = httparse::Response::new(&mut headers);
                    if !matches!(parsed.parse(&response), Ok(httparse::Status::Complete(_)))
                        || !parsed.code.is_some_and(|code| (200..300).contains(&code))
                    {
                        return Err(Error::RustError("invalid HTTP proxy handshake".into()));
                    }
                    if !payload.is_empty() {
                        socket.write_all(payload).await?;
                        socket.flush().await?;
                    }
                }
                ProxyEntry::Direct | ProxyEntry::Tproxy(_) => {
                    return Err(Error::RustError("invalid proxy plan".into()));
                }
            }
            Ok(())
        })
        .await {
            Some(Ok(())) => Ok(socket),
            Some(Err(err)) => {
                drop(socket.close().await);
                Err(err)
            }
            None => {
                drop(socket.close().await);
                Err(Error::RustError(format!(
                    "route connection timed out after {CONNECT_TIMEOUT_MS} ms"
                )))
            }
        }
    }
}

#[allow(clippy::single_call_fn)]
async fn resolve_tproxy_candidates(
    addresses: &[ProxyAddress],
    dns: &DnsService,
) -> Vec<ProxyAddress> {
    let mut candidates = Vec::new();
    let mut fallbacks = Vec::new();
    for address in addresses {
        if candidates.len() == MAX_PROXY_CANDIDATES {
            break;
        }
        if address.host.parse::<IpAddr>().is_ok() {
            if !fallbacks.contains(address) {
                fallbacks.push(address.clone());
            }
            continue;
        }

        if let Ok(records) = dns.resolve_txt(&address.host).await {
            for record in records {
                if candidates.len() == MAX_PROXY_CANDIDATES {
                    break;
                }
                let Ok(targets) = parse_tproxy_servers(&record, address.port) else {
                    continue;
                };
                for (host, port) in targets {
                    if candidates.len() == MAX_PROXY_CANDIDATES {
                        break;
                    }
                    add_tproxy_candidates(&host, port, dns, &mut candidates).await;
                }
            }
        }
        if candidates.len() == MAX_PROXY_CANDIDATES {
            break;
        }
        add_tproxy_candidates(&address.host, address.port, dns, &mut fallbacks).await;
    }

    for fallback in fallbacks {
        if candidates.len() == MAX_PROXY_CANDIDATES {
            break;
        }
        if !candidates.contains(&fallback) {
            candidates.push(fallback);
        }
    }

    candidates
}

async fn add_tproxy_candidates(
    hostname: &str,
    port: u16,
    dns: &DnsService,
    candidates: &mut Vec<ProxyAddress>,
) {
    if candidates.len() >= MAX_PROXY_CANDIDATES {
        return;
    }
    if let Ok(addresses) = dns.resolve(hostname).await {
        for address in addresses {
            let candidate = ProxyAddress {
                host: address.to_string(),
                port,
            };
            if !candidates.contains(&candidate) {
                candidates.push(candidate);
                if candidates.len() == MAX_PROXY_CANDIDATES {
                    break;
                }
            }
        }
    }
}

#[allow(clippy::single_call_fn)]
async fn connect_tproxy_address(
    address: &ProxyAddress,
    payload: &[u8],
    dns: &DnsService,
) -> Result<Socket> {
    let mut socket = connect_tcp(dns, &address.host, address.port).await?;
    match with_timeout(CONNECT_TIMEOUT_MS, async {
        socket.opened().await?;
        if !payload.is_empty() {
            socket.write_all(payload).await?;
            socket.flush().await?;
        }
        Ok(())
    })
    .await
    {
        Some(Ok(())) => Ok(socket),
        Some(Err(err)) => {
            drop(socket.close().await);
            Err(err)
        }
        None => {
            drop(socket.close().await);
            Err(Error::RustError(format!(
                "tproxy connection timed out after {CONNECT_TIMEOUT_MS} ms"
            )))
        }
    }
}
