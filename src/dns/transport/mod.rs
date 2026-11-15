#![allow(clippy::single_call_fn)]

use futures_util::FutureExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use worker::{Error, Result, Socket, Url};

use super::{
    config::{DnsServerConfig, DnsServerType},
    outbound, wire,
};

#[derive(Clone, Debug)]
pub(super) enum Transport {
    Https(outbound::https::Config),
    Socket(SocketConfig),
    Ws(outbound::ws::Config),
}

#[derive(Clone, Debug)]
pub(super) struct SocketConfig {
    host: String,
    port: u16,
    secure: bool,
}

impl SocketConfig {
    fn new(server: &DnsServerConfig, default_port: u16, secure: bool) -> Result<Self> {
        if server.path.is_some() {
            return Err(Error::RustError(
                "invalid DNS config: DNS path is only supported for HTTPS and WebSocket servers"
                    .into(),
            ));
        }
        Ok(Self {
            host: server_host(server)?,
            port: server_port(server, default_port)?,
            secure,
        })
    }
}

impl Transport {
    pub(super) fn from_config(config: &DnsServerConfig) -> Result<Self> {
        match config.kind {
            DnsServerType::Https => outbound::https::Config::new(config).map(Self::Https),
            DnsServerType::Tls => SocketConfig::new(config, 853, true).map(Self::Socket),
            DnsServerType::Tcp => SocketConfig::new(config, 53, false).map(Self::Socket),
            DnsServerType::Ws | DnsServerType::Wss => {
                outbound::ws::Config::new(config).map(Self::Ws)
            }
        }
    }

    fn probe_target(&self) -> Option<(String, u16)> {
        match self {
            Self::Https(config) => probe_url(&config.url, 443),
            Self::Socket(config) => Some((config.host.clone(), config.port)),
            Self::Ws(config) => probe_url(
                &config.url,
                if config.url.starts_with("wss:") {
                    443
                } else {
                    80
                },
            ),
        }
    }
}

fn probe_url(url: &str, default_port: u16) -> Option<(String, u16)> {
    let url = Url::parse(url).ok()?;
    Some((
        url.host_str()?.to_string(),
        url.port().unwrap_or(default_port),
    ))
}

pub(super) async fn exchange(
    transport: &Transport,
    query: &[u8],
    max_message_bytes: usize,
) -> Result<Vec<u8>> {
    match transport {
        Transport::Https(config) => {
            outbound::https::exchange(config, query, max_message_bytes).await
        }
        Transport::Socket(config) => {
            exchange_socket(
                &config.host,
                config.port,
                config.secure,
                query,
                max_message_bytes,
            )
            .await
        }
        Transport::Ws(config) => outbound::ws::exchange(config, query, max_message_bytes).await,
    }
}

pub(super) fn validate_path(path: &str) -> Result<()> {
    if !path.starts_with('/') || path.contains(['?', '#']) {
        return Err(Error::RustError(
            "invalid DNS config: DNS upstream path must be an absolute path".into(),
        ));
    }
    Ok(())
}

pub(super) fn server_host(config: &DnsServerConfig) -> Result<String> {
    let server = config.server.trim();
    if server.is_empty() || server != config.server || server.contains(['/', '?', '#', '@']) {
        return Err(Error::RustError(
            "invalid DNS config: DNS server name must not be empty".into(),
        ));
    }
    Ok(server
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(server)
        .to_string())
}

fn server_port(config: &DnsServerConfig, default_port: u16) -> Result<u16> {
    let port = config.server_port.unwrap_or(default_port);
    if port == 0 {
        return Err(Error::RustError(
            "invalid DNS config: DNS server_port must not be zero".into(),
        ));
    }
    Ok(port)
}

pub(super) fn server_url(
    config: &DnsServerConfig,
    scheme: &str,
    default_port: u16,
    path: &str,
) -> Result<String> {
    let raw_host = server_host(config)?;
    let host = if raw_host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{raw_host}]")
    } else {
        raw_host
    };
    let port = server_port(config, default_port)?;
    let url = Url::parse(&format!("{scheme}://{host}:{port}{path}"))
        .map_err(|_| Error::RustError("invalid DNS config: invalid DNS server address".into()))?;
    if url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.query().is_some()
    {
        return Err(Error::RustError(
            "invalid DNS config: invalid DNS server address".into(),
        ));
    }
    Ok(url.to_string())
}

mod upstream;

pub(super) use upstream::UpstreamPool;

pub(super) struct UpstreamResponse {
    pub(super) bytes: Vec<u8>,
    pub(super) retried_without_ecs: bool,
}

pub(super) async fn exchange_socket(
    host: &str,
    port: u16,
    secure: bool,
    query: &[u8],
    max_message_bytes: usize,
) -> Result<Vec<u8>> {
    let socket = if secure {
        Socket::builder()
            .secure_transport(worker::SecureTransport::On)
            .connect(host.to_string(), port)?
    } else {
        Socket::builder().connect(host.to_string(), port)?
    };
    let mut socket = SocketOnDrop(Some(socket));

    let result = async {
        let socket = socket
            .0
            .as_mut()
            .ok_or_else(|| Error::RustError("DNS upstream socket is unavailable".into()))?;
        socket.opened().await?;
        let length = u16::try_from(query.len())
            .map_err(|_| Error::RustError("DNS query is too large".into()))?;
        socket.write_all(&length.to_be_bytes()).await?;
        socket.write_all(query).await?;
        socket.flush().await?;

        let response_len = usize::from(socket.read_u16().await?);
        if response_len > max_message_bytes {
            return Err(Error::RustError(
                "DNS upstream response is too large".into(),
            ));
        }
        let mut response = vec![0; response_len];
        socket.read_exact(&mut response).await?;
        wire::validate_response(query, &response)?;
        Ok(response)
    }
    .await;
    drop(match socket.0.as_mut() {
        Some(socket) => socket.close().await,
        None => Ok(()),
    });
    socket.0.take();
    result
}

struct SocketOnDrop(Option<Socket>);

impl Drop for SocketOnDrop {
    fn drop(&mut self) {
        if let Some(mut socket) = self.0.take() {
            drop(socket.close().now_or_never());
        }
    }
}
