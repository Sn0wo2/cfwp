use worker::{Env, Result, Url};

pub(crate) struct Config {
    #[cfg_attr(not(feature = "proxy"), allow(dead_code))]
    pub(crate) user_id: String,
    #[cfg(feature = "dns")]
    pub(crate) dns: crate::dns::DnsService,
}

impl Config {
    #[allow(clippy::single_call_fn, clippy::unnecessary_wraps)]
    pub(crate) fn from_env(_env: &Env, _url: &Url, user_id: &str) -> Result<Self> {
        Ok(Self {
            #[cfg(feature = "dns")]
            dns: crate::dns::DnsService::new(_env, &_url.origin().ascii_serialization(), user_id)?,
            user_id: user_id.to_string(),
        })
    }
}
