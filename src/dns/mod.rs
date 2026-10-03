mod cache;
pub(crate) mod config;
pub(crate) mod upstream;
pub(crate) mod util;
pub(crate) mod wire;

use cache::DnsCache;
use config::DnsConfig;
use std::rc::Rc;
use upstream::UpstreamPool;

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
    ) -> worker::Result<Vec<u8>> {
        self.exchange_prepared(self.prepare(payload, client_ip)?)
            .await
    }
}
