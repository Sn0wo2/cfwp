use std::net::{Ipv4Addr, Ipv6Addr};

use base64::Engine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use worker::{Error, Result, Socket};

use super::protocol::InitialRequest;
use super::util::{CONNECT_TIMEOUT_MS, SocketTarget, connect_tcp, split_multi_value};
use crate::util::with_timeout;

#[derive(Clone, Debug)]
pub(super) struct ProxyPlan {
    pub(super) entries: Vec<ProxyEntry>,
}

#[derive(Clone, Debug)]
pub(super) enum ProxyEntry {
    ProxyIp(SocketTarget),
    Socks5(ProxyCredential),
    Http(ProxyCredential),
}

#[derive(Clone, Debug)]
pub(super) struct ProxyCredential {
    host: String,
    port: u16,
    username: Option<String>,
    password: Option<String>,
}

impl ProxyPlan {
    pub(super) async fn connect_via_entries(&self, target: &InitialRequest) -> Result<Socket> {
        let mut last_error = None;

        for entry in &self.entries {
            acta::info!(
                "alternate route attempt: {} -> {}:{}",
                entry.kind_name(),
                target.hostname,
                target.port
            );
            match async {
                let mut socket = match entry {
                    ProxyEntry::ProxyIp(proxy) => connect_tcp(
                        &proxy.host,
                        if proxy.has_explicit_port {
                            proxy.port
                        } else {
                            target.port
                        },
                    ),
                    ProxyEntry::Socks5(proxy) | ProxyEntry::Http(proxy) => {
                        connect_tcp(&proxy.host, proxy.port)
                    }
                }?;
                match with_timeout(CONNECT_TIMEOUT_MS, async {
                        socket.opened().await?;
                        match entry {
                            ProxyEntry::ProxyIp(_) => {
                                write_payload(&mut socket, &target.payload).await?;
                            }
                            ProxyEntry::Socks5(proxy) => {
                                socket
                                    .write_all(if proxy.username.is_some()
                                        && proxy.password.is_some()
                                    {
                                        &[0x05, 0x02, 0x00, 0x02]
                                    } else {
                                        &[0x05, 0x01, 0x00]
                                    })
                                    .await?;

                                let mut response = [0_u8; 2];
                                socket.read_exact(&mut response).await?;
                                if response[0] != 0x05 {
                                    return Err(Error::RustError(
                                        "invalid tunnel version".into(),
                                    ));
                                }
                                if response[1] == 0x02 {
                                    let username =
                                        proxy.username.as_deref().unwrap_or_default().as_bytes();
                                    let password =
                                        proxy.password.as_deref().unwrap_or_default().as_bytes();
                                    if username.len() > u8::MAX as usize
                                        || password.len() > u8::MAX as usize
                                    {
                                        return Err(Error::RustError(
                                            "credential payload too long".into(),
                                        ));
                                    }
                                    let mut auth =
                                        Vec::with_capacity(3 + username.len() + password.len());
                                    auth.push(0x01);
                                    auth.push(username.len() as u8);
                                    auth.extend_from_slice(username);
                                    auth.push(password.len() as u8);
                                    auth.extend_from_slice(password);
                                    socket.write_all(&auth).await?;
                                    socket.read_exact(&mut response).await?;
                                    if response[1] != 0x00 {
                                        return Err(Error::RustError(
                                            "credential check failed".into(),
                                        ));
                                    }
                                } else if response[1] != 0x00 {
                                    return Err(Error::RustError(
                                        "unsupported credential mode".into(),
                                    ));
                                }

                                let mut connect_request = vec![0x05, 0x01, 0x00];
                                if let Ok(ipv4) = target.hostname.parse::<Ipv4Addr>() {
                                    connect_request.push(0x01);
                                    connect_request.extend_from_slice(&ipv4.octets());
                                } else if let Ok(ipv6) = target.hostname.parse::<Ipv6Addr>() {
                                    connect_request.push(0x04);
                                    connect_request.extend_from_slice(&ipv6.octets());
                                } else {
                                    let host = target.hostname.as_bytes();
                                    if host.len() > u8::MAX as usize {
                                        return Err(Error::RustError(
                                            "hostname too long for tunnel".into(),
                                        ));
                                    }
                                    connect_request.extend_from_slice(&[0x03, host.len() as u8]);
                                    connect_request.extend_from_slice(host);
                                }
                                connect_request.extend_from_slice(&target.port.to_be_bytes());
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
                                    _ => {
                                        return Err(Error::RustError(
                                            "invalid bind address".into(),
                                        ));
                                    }
                                };
                                socket
                                    .read_exact(&mut vec![0_u8; address_len + 2])
                                    .await?;
                                write_payload(&mut socket, &target.payload).await?;
                            }
                            ProxyEntry::Http(proxy) => {
                                let authority = if target.hostname.parse::<Ipv6Addr>().is_ok() {
                                    format!("[{}]:{}", target.hostname, target.port)
                                } else {
                                    format!("{}:{}", target.hostname, target.port)
                                };
                                let mut request = format!(
                                    "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: cfwp\r\nProxy-Connection: Keep-Alive\r\n"
                                );
                                if let (Some(username), Some(password)) =
                                    (&proxy.username, &proxy.password)
                                {
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
                                if !matches!(
                                    parsed.parse(&response),
                                    Ok(httparse::Status::Complete(_))
                                ) || !parsed
                                    .code
                                    .is_some_and(|code| (200..300).contains(&code))
                                {
                                    return Err(Error::RustError(
                                        "invalid HTTP proxy handshake".into(),
                                    ));
                                }
                                write_payload(&mut socket, &target.payload).await?;
                            }
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
                                "route connection timed out after {CONNECT_TIMEOUT_MS} ms"
                            )))
                        }
                    }
            }
            .await
            {
                Ok(socket) => {
                    acta::info!("alternate route success: {}", entry.kind_name());
                    return Ok(socket);
                }
                Err(err) => {
                    acta::info!("alternate route failed: {} => {:?}", entry.kind_name(), err);
                    last_error = Some(err);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| Error::RustError("no proxy target available".into())))
    }

    pub(super) fn collect_entries(
        proxy_ip: Option<String>,
        proxy: Option<String>,
        _from_request: bool,
    ) -> Result<Vec<ProxyEntry>> {
        let mut entries = Vec::new();

        if let Some(proxy_ip) = proxy_ip {
            acta::info!(
                "{} route override: ip relay configured",
                if _from_request { "request" } else { "config" }
            );
            for item in split_multi_value(&proxy_ip) {
                entries.push(if item.contains("://") {
                    ProxyEntry::parse(&item)?
                } else {
                    ProxyEntry::ProxyIp({
                        let value = item.trim();
                        let text = if value.parse::<Ipv6Addr>().is_ok() {
                            format!("tcp://[{value}]")
                        } else {
                            format!("tcp://{value}")
                        };
                        let url = worker::Url::parse(&text)
                            .map_err(|_| Error::RustError("invalid proxy target".into()))?;
                        if !matches!(url.path(), "" | "/")
                            || url.query().is_some()
                            || url.fragment().is_some()
                            || !url.username().is_empty()
                            || url.password().is_some()
                            || url.port() == Some(0)
                        {
                            return Err(Error::RustError("invalid proxy target".into()));
                        }
                        let host = url
                            .host_str()
                            .ok_or_else(|| Error::RustError("proxy target needs a host".into()))?;
                        SocketTarget {
                            host: host
                                .strip_prefix('[')
                                .and_then(|value| value.strip_suffix(']'))
                                .unwrap_or(host)
                                .to_string(),
                            port: url.port().unwrap_or(443),
                            has_explicit_port: url.port().is_some(),
                        }
                    })
                });
            }
        }

        if let Some(proxy) = proxy {
            acta::info!(
                "{} route override: proxy relay configured",
                if _from_request { "request" } else { "config" }
            );
            for item in split_multi_value(&proxy) {
                entries.push(ProxyEntry::parse(&item)?);
            }
        }

        Ok(entries)
    }

    pub(super) const fn has_entries(&self) -> bool {
        !self.entries.is_empty()
    }
}

impl ProxyEntry {
    const fn kind_name(&self) -> &'static str {
        match self {
            Self::ProxyIp(_) => "ip-relay",
            Self::Socks5(_) => "socks5",
            Self::Http(_) => "http-connect",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        if !value.contains("://") {
            return Err(Error::RustError(
                "proxy URL must use socks5:// or http://".into(),
            ));
        }
        let url = worker::Url::parse(value.trim())
            .map_err(|_| Error::RustError("invalid proxy URL".into()))?;
        match url.scheme() {
            "socks5" => Ok(Self::Socks5(ProxyCredential::parse(&url, 1080)?)),
            "http" => Ok(Self::Http(ProxyCredential::parse(&url, 80)?)),
            _ => Err(Error::RustError(
                "proxy URL must use socks5:// or http://".into(),
            )),
        }
    }
}

impl ProxyCredential {
    fn parse(url: &worker::Url, default_port: u16) -> Result<Self> {
        if !matches!(url.path(), "" | "/")
            || url.query().is_some()
            || url.fragment().is_some()
            || url.port() == Some(0)
        {
            return Err(Error::RustError("invalid proxy address".into()));
        }
        let raw_host = url
            .host_str()
            .ok_or_else(|| Error::RustError("invalid proxy host".into()))?;
        let host = raw_host
            .strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .unwrap_or(raw_host)
            .to_string();
        let port = url.port().unwrap_or(default_port);
        let has_credentials = !url.username().is_empty() || url.password().is_some();
        let decode = |value: &str| {
            percent_encoding::percent_decode_str(value)
                .decode_utf8()
                .map(std::borrow::Cow::into_owned)
                .map_err(|_| Error::RustError("proxy credentials must be UTF-8".into()))
        };
        let username = has_credentials
            .then(|| decode(url.username()))
            .transpose()?;
        let password = has_credentials
            .then(|| decode(url.password().unwrap_or_default()))
            .transpose()?;

        Ok(Self {
            host,
            port,
            username,
            password,
        })
    }
}
async fn write_payload(socket: &mut Socket, payload: &[u8]) -> Result<()> {
    if payload.is_empty() {
        return Ok(());
    }

    socket.write_all(payload).await?;
    socket.flush().await?;
    Ok(())
}
