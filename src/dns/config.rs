use serde::{Deserialize, Serialize};
use worker::{Error, Result};

const MAX_TIMEOUT_MS: u32 = 60_000;
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum DnsServerType {
    Https,
    Tls,
    Tcp,
    Ws,
    Wss,
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
        return Err(Error::RustError(format!(
            "invalid DNS config: {name} must be between 1 and {MAX_TIMEOUT_MS}"
        )));
    }
    Ok(())
}

pub(crate) fn validate_message_size(name: &str, value: usize) -> Result<()> {
    if !(12..=MAX_MESSAGE_BYTES).contains(&value) {
        return Err(Error::RustError(format!(
            "invalid DNS config: {name} must be between 12 and {MAX_MESSAGE_BYTES}"
        )));
    }
    Ok(())
}
