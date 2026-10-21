use std::collections::HashSet;

use uuid::{Uuid, Version};
use worker::{Error, Result, Url};

use super::TransportConfig;

pub(super) fn validate_tag(tag: &str, tags: &mut HashSet<String>) -> Result<()> {
    if tag.trim().is_empty() || tag.trim() != tag || !tags.insert(tag.to_string()) {
        return Err(Error::RustError(
            "invalid CONFIG: tags must be nonempty and unique".into(),
        ));
    }
    Ok(())
}

pub(super) fn validate_uuid(value: &str) -> Result<String> {
    let uuid = Uuid::parse_str(value)
        .map_err(|_| Error::RustError("invalid CONFIG: user UUID must be a UUIDv4".into()))?;
    if uuid.get_version() != Some(Version::Random) {
        return Err(Error::RustError(
            "invalid CONFIG: user UUID must be a UUIDv4".into(),
        ));
    }
    Ok(uuid.to_string())
}

pub(super) fn validate_unique_credential(
    credentials: &mut HashSet<(String, String)>,
    protocol: &str,
    credential: &str,
) -> Result<()> {
    if !credentials.insert((protocol.to_string(), credential.to_string())) {
        return Err(Error::RustError(
            "invalid CONFIG: inbound credentials must be unique per protocol".into(),
        ));
    }
    Ok(())
}

pub(super) fn validate_transport(transport: Option<&TransportConfig>) -> Result<()> {
    if let Some(TransportConfig::Ws(config)) = transport
        && (!config.path.starts_with('/') || config.path.contains(['?', '#']))
    {
        return Err(Error::RustError(
            "invalid CONFIG: WebSocket transport path must be an absolute path".into(),
        ));
    }
    Ok(())
}

pub(super) fn validate_server(server: &str, port: u16) -> Result<()> {
    if server.trim().is_empty()
        || server.trim() != server
        || server.contains(['/', '?', '#', '@'])
        || port == 0
    {
        return Err(Error::RustError(
            "invalid CONFIG: outbound server and server_port are invalid".into(),
        ));
    }
    let raw_host = server
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(server);
    let host = if raw_host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{raw_host}]")
    } else {
        raw_host.to_string()
    };
    let url = Url::parse(&format!("tcp://{host}:{port}"))
        .map_err(|_| Error::RustError("invalid CONFIG: outbound server is invalid".into()))?;
    if url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || !matches!(url.path(), "" | "/")
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(Error::RustError(
            "invalid CONFIG: outbound server is invalid".into(),
        ));
    }
    Ok(())
}

pub(crate) fn parse_tproxy_servers(server: &str, default_port: u16) -> Result<Vec<(String, u16)>> {
    if server.trim().is_empty() || default_port == 0 {
        return Err(Error::RustError(
            "invalid CONFIG: tproxy server addresses are invalid".into(),
        ));
    }

    let mut addresses = Vec::new();
    for candidate in server.split(',') {
        let candidate = candidate.trim();
        if candidate.is_empty() || candidate.contains(['/', '?', '#', '@', '{', '}']) {
            return Err(Error::RustError(
                "invalid CONFIG: tproxy server addresses are invalid".into(),
            ));
        }

        let (host, port) = if let Ok(address) = candidate.parse::<std::net::Ipv6Addr>() {
            (address.to_string(), default_port)
        } else {
            let url = Url::parse(&format!("tcp://{candidate}")).map_err(|_| {
                Error::RustError("invalid CONFIG: tproxy server address is invalid".into())
            })?;
            let host = url
                .host_str()
                .and_then(|host| {
                    host.strip_prefix('[')
                        .and_then(|value| value.strip_suffix(']'))
                        .or(Some(host))
                })
                .ok_or_else(|| {
                    Error::RustError("invalid CONFIG: tproxy server address is invalid".into())
                })?;
            if !url.username().is_empty()
                || url.password().is_some()
                || !matches!(url.path(), "" | "/")
                || url.query().is_some()
                || url.fragment().is_some()
            {
                return Err(Error::RustError(
                    "invalid CONFIG: tproxy server address is invalid".into(),
                ));
            }
            (host.to_string(), url.port().unwrap_or(default_port))
        };

        if port == 0 {
            return Err(Error::RustError(
                "invalid CONFIG: tproxy server port is invalid".into(),
            ));
        }
        addresses.push((host, port));
        if addresses.len() > 16 {
            return Err(Error::RustError(
                "invalid CONFIG: too many tproxy server addresses".into(),
            ));
        }
    }

    Ok(addresses)
}
