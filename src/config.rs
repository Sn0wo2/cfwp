use std::collections::HashSet;

use serde::Deserialize;
use uuid::{Uuid, Version};
use worker::{Env, Error, Result, Url};

use crate::dns::DnsService;

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
        let value = env
            .var("CONFIG")
            .map_err(|_| Error::RustError("CONFIG is required".into()))?;
        let settings: Settings = serde_json::from_str(&value.to_string())
            .map_err(|_| Error::RustError("CONFIG must contain valid JSON".into()))?;
        settings.validate()?;
        let dns = DnsService::new(settings.dns, origin)?;
        Ok(Self {
            inbounds: settings.inbounds,
            outbounds: settings.outbounds,
            route: settings.route,
            dns,
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
            return Err(config_error("inbounds must not be empty"));
        }
        if self.outbounds.is_empty() {
            return Err(config_error("outbounds must not be empty"));
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
                            return Err(config_error("only an empty VLESS user flow is supported"));
                        }
                        validate_unique_credential(&mut credentials, "vless", &uuid)?;
                    }
                    validate_transport(config.transport.as_ref())?;
                }
                InboundConfig::Vmess(config) => {
                    for user in &config.users {
                        let uuid = validate_uuid(&user.uuid)?;
                        if user.alter_id != 0 {
                            return Err(config_error("VMess alterId must be 0"));
                        }
                        validate_unique_credential(&mut credentials, "vmess", &uuid)?;
                    }
                    validate_transport(config.transport.as_ref())?;
                }
                InboundConfig::Trojan(config) => {
                    for user in &config.users {
                        if user.password.is_empty() {
                            return Err(config_error("Trojan passwords must not be empty"));
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
                        return Err(config_error("unsupported Shadowsocks method"));
                    }
                    if config.password.is_empty() {
                        return Err(config_error("Shadowsocks password must not be empty"));
                    }
                    validate_unique_credential(
                        &mut credentials,
                        &format!("shadowsocks:{}", config.method),
                        &config.password,
                    )?;
                    validate_transport(config.transport.as_ref())?;
                }
            }
            if inbound.has_no_users() {
                return Err(config_error("inbound users must not be empty"));
            }
        }

        for outbound in &self.outbounds {
            validate_tag(outbound.tag(), &mut tags)?;
            match outbound {
                OutboundConfig::Direct(_) => {}
                OutboundConfig::Socks(config) => {
                    validate_server(&config.server, config.server_port)?;
                    let has_username = config.username.is_some();
                    let has_password = config.password.is_some();
                    match config.version.as_str() {
                        "4" => {
                            if config.password.is_some()
                                || config.username.as_deref().is_some_and(|value| {
                                    value.len() > u8::MAX as usize || value.contains('\0')
                                })
                            {
                                return Err(config_error("invalid SOCKS4 credentials"));
                            }
                        }
                        "5" => {
                            if has_username != has_password
                                || config
                                    .username
                                    .as_deref()
                                    .is_some_and(|value| value.len() > u8::MAX as usize)
                                || config
                                    .password
                                    .as_deref()
                                    .is_some_and(|value| value.len() > u8::MAX as usize)
                            {
                                return Err(config_error("invalid SOCKS5 credentials"));
                            }
                        }
                        _ => return Err(config_error("SOCKS version must be 4 or 5")),
                    }
                }
                OutboundConfig::Http(config) => {
                    validate_server(&config.server, config.server_port)?;
                    if config.username.is_some() != config.password.is_some() {
                        return Err(config_error(
                            "HTTP username and password must be configured together",
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
            return Err(config_error("route.final must reference an outbound tag"));
        }
        Ok(())
    }
}

fn validate_tag(tag: &str, tags: &mut HashSet<String>) -> Result<()> {
    if tag.trim().is_empty() || tag.trim() != tag || !tags.insert(tag.to_string()) {
        return Err(config_error("tags must be nonempty and unique"));
    }
    Ok(())
}

fn validate_uuid(value: &str) -> Result<String> {
    let uuid = Uuid::parse_str(value).map_err(|_| config_error("user UUID must be a UUIDv4"))?;
    if uuid.get_version() != Some(Version::Random) {
        return Err(config_error("user UUID must be a UUIDv4"));
    }
    Ok(uuid.to_string())
}

fn validate_unique_credential(
    credentials: &mut HashSet<(String, String)>,
    protocol: &str,
    credential: &str,
) -> Result<()> {
    if !credentials.insert((protocol.to_string(), credential.to_string())) {
        return Err(config_error(
            "inbound credentials must be unique per protocol",
        ));
    }
    Ok(())
}

fn validate_transport(transport: Option<&TransportConfig>) -> Result<()> {
    if let Some(TransportConfig::Ws(config)) = transport
        && (!config.path.starts_with('/') || config.path.contains(['?', '#']))
    {
        return Err(config_error(
            "WebSocket transport path must be an absolute path",
        ));
    }
    Ok(())
}

fn validate_server(server: &str, port: u16) -> Result<()> {
    if server.trim().is_empty()
        || server.trim() != server
        || server.contains(['/', '?', '#', '@'])
        || port == 0
    {
        return Err(config_error("outbound server and server_port are invalid"));
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
        .map_err(|_| config_error("outbound server is invalid"))?;
    if url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || !matches!(url.path(), "" | "/")
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(config_error("outbound server is invalid"));
    }
    Ok(())
}

const MAX_TPROXY_SERVERS: usize = 16;

pub(crate) fn parse_tproxy_servers(server: &str, default_port: u16) -> Result<Vec<(String, u16)>> {
    if server.trim().is_empty() || default_port == 0 {
        return Err(config_error("tproxy server addresses are invalid"));
    }

    let mut addresses = Vec::new();
    for candidate in server.split(',') {
        let candidate = candidate.trim();
        if candidate.is_empty() || candidate.contains(['/', '?', '#', '@', '{', '}']) {
            return Err(config_error("tproxy server addresses are invalid"));
        }

        let (host, port) = if let Ok(address) = candidate.parse::<std::net::Ipv6Addr>() {
            (address.to_string(), default_port)
        } else {
            let url = Url::parse(&format!("tcp://{candidate}"))
                .map_err(|_| config_error("tproxy server address is invalid"))?;
            let host = url
                .host_str()
                .and_then(|host| {
                    host.strip_prefix('[')
                        .and_then(|value| value.strip_suffix(']'))
                        .or(Some(host))
                })
                .ok_or_else(|| config_error("tproxy server address is invalid"))?;
            if !url.username().is_empty()
                || url.password().is_some()
                || !matches!(url.path(), "" | "/")
                || url.query().is_some()
                || url.fragment().is_some()
            {
                return Err(config_error("tproxy server address is invalid"));
            }
            (host.to_string(), url.port().unwrap_or(default_port))
        };

        if port == 0 {
            return Err(config_error("tproxy server port is invalid"));
        }
        addresses.push((host, port));
        if addresses.len() > MAX_TPROXY_SERVERS {
            return Err(config_error("too many tproxy server addresses"));
        }
    }

    Ok(addresses)
}

const fn default_tproxy_server_port() -> u16 {
    443
}

fn config_error(message: &str) -> Error {
    Error::RustError(format!("invalid CONFIG: {message}"))
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

    const fn has_no_users(&self) -> bool {
        match self {
            Self::Vless(config) => config.users.is_empty(),
            Self::Vmess(config) => config.users.is_empty(),
            Self::Trojan(config) => config.users.is_empty(),
            Self::Shadowsocks(_) => false,
        }
    }

    pub(crate) fn accepts_path(&self, path: &str) -> bool {
        match self {
            Self::Vless(config) => config
                .transport
                .as_ref()
                .is_none_or(|transport| transport.path() == path),
            Self::Vmess(config) => config
                .transport
                .as_ref()
                .is_none_or(|transport| transport.path() == path),
            Self::Trojan(config) => config
                .transport
                .as_ref()
                .is_none_or(|transport| transport.path() == path),
            Self::Shadowsocks(config) => config
                .transport
                .as_ref()
                .is_none_or(|transport| transport.path() == path),
        }
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

impl TransportConfig {
    fn path(&self) -> &str {
        match self {
            Self::Ws(config) => &config.path,
        }
    }
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
