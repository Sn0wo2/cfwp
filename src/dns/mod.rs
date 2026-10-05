mod cache;
pub(crate) mod config;
pub(crate) mod upstream;
pub(crate) mod util;
pub(crate) mod wire;

use cache::DnsCache;
use config::DnsConfig;
use std::fmt;
use std::rc::Rc;
use upstream::UpstreamPool;
use worker::Error;

#[derive(Debug)]
pub(crate) enum DnsError {
    TooLarge,
    Timeout(u32),
    Other(Error),
}

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge => f.write_str("DNS message too large"),
            Self::Timeout(timeout_ms) => {
                write!(f, "DNS request timed out after {timeout_ms} ms")
            }
            Self::Other(err) => write!(f, "{err}"),
        }
    }
}

impl From<Error> for DnsError {
    fn from(err: Error) -> Self {
        Self::Other(err)
    }
}

impl From<DnsError> for Error {
    fn from(err: DnsError) -> Self {
        match err {
            DnsError::TooLarge => Self::RustError("DNS message too large".into()),
            DnsError::Timeout(timeout_ms) => {
                Self::RustError(format!("DNS request timed out after {timeout_ms} ms"))
            }
            DnsError::Other(err) => err,
        }
    }
}

pub(crate) type DnsResult<T> = Result<T, DnsError>;

#[derive(Clone)]
pub(crate) struct DnsService {
    pub(crate) config: Rc<DnsConfig>,
    upstreams: UpstreamPool,
    cache: Option<Rc<DnsCache>>,
}

#[allow(clippy::multiple_inherent_impl)]
impl DnsService {
    #[cfg(feature = "proxy")]
    pub(crate) async fn exchange(
        &self,
        payload: &[u8],
        client_ip: Option<std::net::IpAddr>,
    ) -> DnsResult<Vec<u8>> {
        self.exchange_prepared(self.prepare(payload, client_ip)?)
            .await
    }
}
