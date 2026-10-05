use std::borrow::Cow;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::exhaustive_enums)]
pub enum ParseError {
    Truncated,
    Invalid(&'static str),
}
impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("truncated address"),
            Self::Invalid(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for ParseError {}

#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(clippy::exhaustive_enums)]
pub enum SocksAddr {
    V4(SocketAddrV4),
    Domain(String, u16),
    V6(SocketAddrV6),
}

impl SocksAddr {
    pub fn parse_socks(buf: &[u8]) -> Result<(Self, usize), ParseError> {
        let (addr, consumed) = parse_addr(buf, true)?;
        let Some(port_bytes) = buf
            .get(consumed..)
            .and_then(|tail| tail.get(..2))
            .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
        else {
            return Err(ParseError::Truncated);
        };
        let port = u16::from_be_bytes(port_bytes);
        Ok((addr.with_port(port), consumed + port_bytes.len()))
    }

    pub fn parse_xray(buf: &[u8]) -> Result<(Self, usize), ParseError> {
        let Some(port_bytes) = buf
            .get(..2)
            .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
        else {
            return Err(ParseError::Truncated);
        };
        let Some(address_bytes) = buf.get(2..) else {
            return Err(ParseError::Truncated);
        };
        let port = u16::from_be_bytes(port_bytes);
        let (addr, consumed) = parse_addr(address_bytes, false)?;
        Ok((addr.with_port(port), consumed + port_bytes.len()))
    }

    pub fn host(&self) -> Cow<'_, str> {
        match self {
            Self::V4(addr) => Cow::Owned(addr.ip().to_string()),
            Self::Domain(domain, _) => Cow::Borrowed(domain),
            Self::V6(addr) => Cow::Owned(addr.ip().to_string()),
        }
    }

    pub const fn port(&self) -> u16 {
        match self {
            Self::V4(addr) => addr.port(),
            Self::Domain(_, port) => *port,
            Self::V6(addr) => addr.port(),
        }
    }

    pub fn is_routable(&self) -> bool {
        if self.port() == 0 {
            return false;
        }
        match self {
            Self::V4(_) | Self::V6(_) => true,
            Self::Domain(host, _) => {
                let host = host.strip_suffix('.').unwrap_or(host);
                host.is_ascii()
                    && host.len() <= 254
                    && host.split('.').all(|label| {
                        let label = label.as_bytes();
                        !label.is_empty()
                            && label.len() <= 63
                            && label.first().is_some_and(u8::is_ascii_alphanumeric)
                            && label.last().is_some_and(u8::is_ascii_alphanumeric)
                            && label
                                .iter()
                                .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
                    })
            }
        }
    }

    fn with_port(self, port: u16) -> Self {
        match self {
            Self::V4(addr) => Self::V4(SocketAddrV4::new(*addr.ip(), port)),
            Self::Domain(domain, _) => Self::Domain(domain, port),
            Self::V6(addr) => Self::V6(SocketAddrV6::new(*addr.ip(), port, 0, 0)),
        }
    }
}

impl fmt::Display for SocksAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.host(), self.port())
    }
}

fn parse_addr(buf: &[u8], socks_family: bool) -> Result<(SocksAddr, usize), ParseError> {
    let Some(family) = buf.first().copied() else {
        return Err(ParseError::Truncated);
    };
    let domain_family = if socks_family { 3 } else { 2 };
    let ipv6_family = if socks_family { 4 } else { 3 };
    match family {
        1 => {
            let Some(octets) = buf
                .get(1..5)
                .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
            else {
                return Err(ParseError::Truncated);
            };
            Ok((
                SocksAddr::V4(SocketAddrV4::new(Ipv4Addr::from(octets), 0)),
                5,
            ))
        }
        family if family == domain_family => {
            let Some(len) = buf.get(1).copied().map(usize::from) else {
                return Err(ParseError::Truncated);
            };
            let Some(domain_bytes) = buf.get(2..2 + len) else {
                return Err(ParseError::Truncated);
            };
            let domain = std::str::from_utf8(domain_bytes)
                .map_err(|_| ParseError::Invalid("invalid domain encoding"))?;
            Ok((SocksAddr::Domain(domain.to_owned(), 0), 2 + len))
        }
        family if family == ipv6_family => {
            let Some(octets) = buf
                .get(1..17)
                .and_then(|bytes| <[u8; 16]>::try_from(bytes).ok())
            else {
                return Err(ParseError::Truncated);
            };
            Ok((
                SocksAddr::V6(SocketAddrV6::new(Ipv6Addr::from(octets), 0, 0, 0)),
                17,
            ))
        }
        _ => Err(ParseError::Invalid("invalid address family")),
    }
}
