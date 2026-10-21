use serde::{Deserialize, Serialize};
use worker::{Error, Result, Url};

const MAX_TIMEOUT_MS: u32 = 60_000;
pub(crate) const MAX_SERVERS: usize = 16;
const MAX_MESSAGE_BYTES: usize = 65_535;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct DnsConfig {
    pub servers: Vec<DnsServerConfig>,
    pub strategy: Strategy,
    pub address_family: AddressFamily,
    pub timeout_ms: u32,
    pub request_timeout_ms: u32,
    pub race_concurrency: usize,
    pub probe: Option<String>,
    pub max_message_bytes: usize,
    pub ecs: Option<EcsConfig>,
    pub cache: Option<CacheConfig>,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            servers: vec![DnsServerConfig {
                kind: DnsServerType::Https,
                tag: Some("google".into()),
                server: "dns.google".into(),
                server_port: Some(443),
                path: Some("/dns-query".into()),
            }],
            strategy: Strategy::None,
            address_family: AddressFamily::None,
            timeout_ms: 2_000,
            request_timeout_ms: 5_000,
            race_concurrency: 2,
            probe: None,
            max_message_bytes: MAX_MESSAGE_BYTES,
            ecs: None,
            cache: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DnsServerConfig {
    #[serde(rename = "type")]
    pub kind: DnsServerType,
    #[serde(default)]
    pub tag: Option<String>,
    pub server: String,
    #[serde(default)]
    pub server_port: Option<u16>,
    #[serde(default)]
    pub path: Option<String>,
}

impl DnsServerConfig {
    pub(crate) fn url(&self) -> Result<String> {
        let server = self.server.trim();
        if server.is_empty() || server != self.server || server.contains(['/', '?', '#', '@']) {
            return Err(config_error("DNS server name must not be empty"));
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
        let (scheme, default_port) = match self.kind {
            DnsServerType::Https => ("https", 443),
            DnsServerType::Tls => ("tls", 853),
            DnsServerType::Tcp => ("tcp", 53),
        };
        let port = self.server_port.unwrap_or(default_port);
        if port == 0 {
            return Err(config_error("DNS server_port must not be zero"));
        }
        let path = if self.kind == DnsServerType::Https {
            let path = self.path.as_deref().unwrap_or("/dns-query");
            if !path.starts_with('/') || path.contains(['?', '#']) {
                return Err(config_error("DNS HTTPS path must be an absolute path"));
            }
            path
        } else {
            if self.path.is_some() {
                return Err(config_error("DNS path is only supported for HTTPS servers"));
            }
            ""
        };
        let url = Url::parse(&format!("{scheme}://{host}:{port}{path}"))
            .map_err(|_| config_error("invalid DNS server address"))?;
        if url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
            || url.query().is_some()
        {
            return Err(config_error("invalid DNS server address"));
        }
        Ok(url.to_string())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum DnsServerType {
    Https,
    Tls,
    Tcp,
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Strategy {
    #[default]
    None,
    First,
    FastestV4,
    FastestV6,
    FastestAll,
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AddressFamily {
    #[default]
    None,
    PerfV4,
    PerfV6,
    OnlyV4,
    OnlyV6,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct EcsConfig {
    pub ipv4_prefix: u8,
    pub ipv6_prefix: u8,
    pub strip_injected: bool,
    pub retry_without_ecs: bool,
}

impl Default for EcsConfig {
    fn default() -> Self {
        Self {
            ipv4_prefix: 32,
            ipv6_prefix: 128,
            strip_injected: true,
            retry_without_ecs: true,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct CacheConfig {
    pub max_ttl: u32,
    pub max_message_bytes: usize,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_ttl: 300,
            max_message_bytes: 16_384,
        }
    }
}

pub(crate) fn validate_timeout(name: &str, value: u32) -> Result<()> {
    if value == 0 || value > MAX_TIMEOUT_MS {
        return Err(config_error(&format!(
            "{name} must be between 1 and {MAX_TIMEOUT_MS}"
        )));
    }
    Ok(())
}

pub(crate) fn validate_message_size(name: &str, value: usize) -> Result<()> {
    if !(12..=MAX_MESSAGE_BYTES).contains(&value) {
        return Err(config_error(&format!(
            "{name} must be between 12 and {MAX_MESSAGE_BYTES}"
        )));
    }
    Ok(())
}

pub(crate) fn config_error(message: &str) -> Error {
    Error::RustError(format!("invalid DNS config: {message}"))
}
