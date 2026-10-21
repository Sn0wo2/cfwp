use std::collections::HashSet;

mod utils;

use serde::Deserialize;
use worker::{Env, Error, Result};

use crate::dns::DnsService;
pub(crate) use utils::parse_tproxy_servers;
use utils::{
    validate_server, validate_tag, validate_transport, validate_unique_credential, validate_uuid,
};

pub(crate) struct Config {
    pub(crate) inbounds: Vec<InboundConfig>,
    pub(crate) outbounds: Vec<OutboundConfig>,
    pub(crate) route: RouteConfig,
    pub(crate) dns: DnsService,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    inbounds: Vec<InboundConfig>,
    outbounds: Vec<OutboundConfig>,
    route: RouteConfig,
    dns: crate::dns::config::DnsConfig,
}

impl Config {
    #[allow(clippy::single_call_fn)]
    pub(crate) fn from_env(env: &Env, origin: &str) -> Result<Self> {
        let settings: Settings = serde_json::from_str(
            &env.var("CONFIG")
                .map_err(|_| Error::RustError("CONFIG is required".into()))?
                .to_string(),
        )
        .map_err(|_| Error::RustError("CONFIG must contain valid JSON".into()))?;
        settings.validate()?;
        Ok(Self {
            inbounds: settings.inbounds,
            outbounds: settings.outbounds,
            route: settings.route,
            dns: DnsService::new(settings.dns, origin)?,
        })
    }

    pub(crate) fn final_outbound(&self) -> Option<&OutboundConfig> {
        self.outbounds
            .iter()
            .find(|outbound| outbound.tag() == self.route.final_outbound)
    }
}

impl Settings {
    fn validate(&self) -> Result<()> {
        if self.inbounds.is_empty() {
            return Err(Error::RustError(
                "invalid CONFIG: inbounds must not be empty".into(),
            ));
        }
        if self.outbounds.is_empty() {
            return Err(Error::RustError(
                "invalid CONFIG: outbounds must not be empty".into(),
            ));
        }

        let mut tags = HashSet::new();
        let mut credentials = HashSet::new();
        for inbound in &self.inbounds {
            validate_tag(inbound.tag(), &mut tags)?;
            match inbound {
                InboundConfig::Vless(config) => {
                    for user in &config.users {
                        let uuid = validate_uuid(&user.uuid)?;
                        if user.flow.as_deref().is_some_and(|flow| !flow.is_empty()) {
                            return Err(Error::RustError(
                                "invalid CONFIG: only an empty VLESS user flow is supported".into(),
                            ));
                        }
                        validate_unique_credential(&mut credentials, "vless", &uuid)?;
                    }
                    validate_transport(config.transport.as_ref())?;
                }
                InboundConfig::Vmess(config) => {
                    for user in &config.users {
                        let uuid = validate_uuid(&user.uuid)?;
                        if user.alter_id != 0 {
                            return Err(Error::RustError(
                                "invalid CONFIG: VMess alterId must be 0".into(),
                            ));
                        }
                        validate_unique_credential(&mut credentials, "vmess", &uuid)?;
                    }
                    validate_transport(config.transport.as_ref())?;
                }
                InboundConfig::Trojan(config) => {
                    for user in &config.users {
                        if user.password.is_empty() {
                            return Err(Error::RustError(
                                "invalid CONFIG: Trojan passwords must not be empty".into(),
                            ));
                        }
                        validate_unique_credential(&mut credentials, "trojan", &user.password)?;
                    }
                    validate_transport(config.transport.as_ref())?;
                }
                InboundConfig::Shadowsocks(config) => {
                    if !matches!(
                        config.method.as_str(),
                        "aes-128-gcm" | "aes-256-gcm" | "chacha20-ietf-poly1305"
                    ) {
                        return Err(Error::RustError(
                            "invalid CONFIG: unsupported Shadowsocks method".into(),
                        ));
                    }
                    if config.password.is_empty() {
                        return Err(Error::RustError(
                            "invalid CONFIG: Shadowsocks password must not be empty".into(),
                        ));
                    }
                    validate_unique_credential(
                        &mut credentials,
                        &format!("shadowsocks:{}", config.method),
                        &config.password,
                    )?;
                    validate_transport(config.transport.as_ref())?;
                }
            }
            if match inbound {
                InboundConfig::Vless(config) => config.users.is_empty(),
                InboundConfig::Vmess(config) => config.users.is_empty(),
                InboundConfig::Trojan(config) => config.users.is_empty(),
                InboundConfig::Shadowsocks(_) => false,
            } {
                return Err(Error::RustError(
                    "invalid CONFIG: inbound users must not be empty".into(),
                ));
            }
        }

        for outbound in &self.outbounds {
            validate_tag(outbound.tag(), &mut tags)?;
            match outbound {
                OutboundConfig::Direct(_) => {}
                OutboundConfig::Socks(config) => {
                    validate_server(&config.server, config.server_port)?;
                    match config.version.as_str() {
                        "4" => {
                            if config.password.is_some()
                                || config.username.as_deref().is_some_and(|value| {
                                    value.len() > u8::MAX as usize || value.contains('\0')
                                })
                            {
                                return Err(Error::RustError(
                                    "invalid CONFIG: invalid SOCKS4 credentials".into(),
                                ));
                            }
                        }
                        "5" => {
                            if config.username.is_some() != config.password.is_some()
                                || config
                                    .username
                                    .as_deref()
                                    .is_some_and(|value| value.len() > u8::MAX as usize)
                                || config
                                    .password
                                    .as_deref()
                                    .is_some_and(|value| value.len() > u8::MAX as usize)
                            {
                                return Err(Error::RustError(
                                    "invalid CONFIG: invalid SOCKS5 credentials".into(),
                                ));
                            }
                        }
                        _ => {
                            return Err(Error::RustError(
                                "invalid CONFIG: SOCKS version must be 4 or 5".into(),
                            ));
                        }
                    }
                }
                OutboundConfig::Http(config) => {
                    validate_server(&config.server, config.server_port)?;
                    if config.username.is_some() != config.password.is_some() {
                        return Err(Error::RustError(
                            "invalid CONFIG: HTTP username and password must be configured together"
                                .into(),
                        ));
                    }
                }
                OutboundConfig::Tproxy(config) => {
                    parse_tproxy_servers(
                        &config.server.replace("{colo}", "sfo"),
                        config.server_port,
                    )?;
                }
            }
        }

        if self.route.final_outbound.is_empty()
            || !self
                .outbounds
                .iter()
                .any(|outbound| outbound.tag() == self.route.final_outbound)
        {
            return Err(Error::RustError(
                "invalid CONFIG: route.final must reference an outbound tag".into(),
            ));
        }
        Ok(())
    }
}

const fn default_tproxy_server_port() -> u16 {
    443
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RouteConfig {
    #[serde(rename = "final")]
    final_outbound: String,
}

#[derive(Clone, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub(crate) enum InboundConfig {
    Vless(VlessInbound),
    Vmess(VmessInbound),
    Trojan(TrojanInbound),
    Shadowsocks(ShadowsocksInbound),
}

impl InboundConfig {
    pub(crate) fn tag(&self) -> &str {
        match self {
            Self::Vless(config) => &config.tag,
            Self::Vmess(config) => &config.tag,
            Self::Trojan(config) => &config.tag,
            Self::Shadowsocks(config) => &config.tag,
        }
    }

    pub(crate) fn accepts_path(&self, path: &str) -> bool {
        (match self {
            Self::Vless(config) => config.transport.as_ref(),
            Self::Vmess(config) => config.transport.as_ref(),
            Self::Trojan(config) => config.transport.as_ref(),
            Self::Shadowsocks(config) => config.transport.as_ref(),
        })
        .is_none_or(|transport| match transport {
            TransportConfig::Ws(config) => config.path == path,
        })
    }
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct VlessInbound {
    pub(crate) tag: String,
    pub(crate) users: Vec<VlessUser>,
    #[serde(default)]
    pub(crate) transport: Option<TransportConfig>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct VlessUser {
    #[serde(default, rename = "name")]
    pub(crate) _name: String,
    pub(crate) uuid: String,
    #[serde(default)]
    pub(crate) flow: Option<String>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct VmessInbound {
    pub(crate) tag: String,
    pub(crate) users: Vec<VmessUser>,
    #[serde(default)]
    pub(crate) transport: Option<TransportConfig>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct VmessUser {
    #[serde(default, rename = "name")]
    pub(crate) _name: String,
    pub(crate) uuid: String,
    #[serde(default, rename = "alterId")]
    pub(crate) alter_id: u16,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TrojanInbound {
    pub(crate) tag: String,
    pub(crate) users: Vec<TrojanUser>,
    #[serde(default)]
    pub(crate) transport: Option<TransportConfig>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TrojanUser {
    #[serde(default, rename = "name")]
    pub(crate) _name: String,
    pub(crate) password: String,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ShadowsocksInbound {
    pub(crate) tag: String,
    pub(crate) method: String,
    pub(crate) password: String,
    #[serde(default)]
    pub(crate) transport: Option<TransportConfig>,
}

#[derive(Clone, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub(crate) enum TransportConfig {
    Ws(WsTransport),
}

#[derive(Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct WsTransport {
    pub(crate) path: String,
}

impl Default for WsTransport {
    fn default() -> Self {
        Self { path: "/".into() }
    }
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub(crate) enum OutboundConfig {
    Direct(DirectOutbound),
    Socks(SocksOutbound),
    Http(HttpOutbound),
    Tproxy(TproxyOutbound),
}

impl OutboundConfig {
    pub(crate) fn tag(&self) -> &str {
        match self {
            Self::Direct(config) => &config.tag,
            Self::Socks(config) => &config.tag,
            Self::Http(config) => &config.tag,
            Self::Tproxy(config) => &config.tag,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DirectOutbound {
    pub(crate) tag: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SocksOutbound {
    pub(crate) tag: String,
    pub(crate) version: String,
    pub(crate) server: String,
    pub(crate) server_port: u16,
    #[serde(default)]
    pub(crate) username: Option<String>,
    #[serde(default)]
    pub(crate) password: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HttpOutbound {
    pub(crate) tag: String,
    pub(crate) server: String,
    pub(crate) server_port: u16,
    #[serde(default)]
    pub(crate) username: Option<String>,
    #[serde(default)]
    pub(crate) password: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TproxyOutbound {
    pub(crate) tag: String,
    pub(crate) server: String,
    #[serde(default = "default_tproxy_server_port")]
    pub(crate) server_port: u16,
}
