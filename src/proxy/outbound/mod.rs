#[allow(clippy::single_call_fn)]
mod http;
#[allow(clippy::single_call_fn)]
mod socks4;
#[allow(clippy::single_call_fn)]
mod socks5;
#[allow(clippy::single_call_fn)]
mod tproxy;
mod utils;

use tokio::io::AsyncWriteExt;
use worker::{Error, Result, Socket};

use super::util::open_and_send;
use crate::config::{Config, OutboundConfig};
use crate::dns::DnsService;
use crate::util::with_timeout;

#[derive(Clone)]
pub(super) enum ProxyPlan {
    Direct,
    Tproxy(Vec<(String, u16)>),
    Socks4(ProxyCredential),
    Socks5(ProxyCredential),
    Http(ProxyCredential),
}

#[derive(Clone)]
pub(super) struct ProxyCredential {
    host: String,
    port: u16,
    username: Option<String>,
    password: Option<String>,
}

impl ProxyPlan {
    #[allow(clippy::single_call_fn, clippy::literal_string_with_formatting_args)]
    pub(super) fn from_config(config: &Config, colo: Option<&str>) -> Result<Self> {
        Ok(
            match config.final_outbound().ok_or_else(|| {
                Error::RustError("route.final references an unknown outbound".into())
            })? {
                OutboundConfig::Direct(_) => Self::Direct,
                OutboundConfig::Socks(config) => {
                    let proxy = ProxyCredential {
                        host: config.server.clone(),
                        port: config.server_port,
                        username: config.username.clone(),
                        password: config.password.clone(),
                    };
                    match config.version.as_str() {
                        "4" => Self::Socks4(proxy),
                        "5" => Self::Socks5(proxy),
                        _ => return Err(Error::RustError("unsupported SOCKS version".into())),
                    }
                }
                OutboundConfig::Http(config) => Self::Http(ProxyCredential {
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
                    Self::Tproxy(if servers.is_empty() {
                        Vec::new()
                    } else {
                        crate::config::parse_tproxy_servers(&servers, config.server_port)?
                    })
                }
            },
        )
    }

    pub(super) async fn connect(
        &self,
        hostname: &str,
        port: u16,
        payload: &[u8],
        dns: &DnsService,
    ) -> Result<Socket> {
        let proxy = match self {
            Self::Direct => {
                return open_and_send(
                    utils::connect_tcp(dns, hostname, port).await?,
                    payload,
                    "target",
                )
                .await;
            }
            Self::Tproxy(addresses) => return tproxy::connect(addresses, payload, dns).await,
            Self::Socks4(proxy) | Self::Socks5(proxy) | Self::Http(proxy) => proxy,
        };
        let target_address = dns
            .resolve(hostname)
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| Error::RustError("DNS returned no usable addresses".into()))?;
        let mut socket = utils::connect_tcp(dns, &proxy.host, proxy.port).await?;
        match with_timeout(10_000, async {
            socket.opened().await?;
            match self {
                Self::Socks4(_) => {
                    socks4::handshake(&mut socket, proxy, target_address, port).await?;
                }
                Self::Socks5(_) => {
                    socks5::handshake(&mut socket, proxy, target_address, port).await?;
                }
                Self::Http(_) => {
                    http::handshake(&mut socket, proxy, target_address, port).await?;
                }
                Self::Direct | Self::Tproxy(_) => {
                    return Err(Error::RustError("invalid proxy plan".into()));
                }
            }
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
                Err(Error::RustError(
                    "route connection timed out after 10000 ms".into(),
                ))
            }
        }
    }
}
