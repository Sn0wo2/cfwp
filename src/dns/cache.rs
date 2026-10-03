use super::config::CacheConfig;

pub(super) struct DnsCache {
    pub(super) prefix: String,
    pub(super) config: CacheConfig,
}
