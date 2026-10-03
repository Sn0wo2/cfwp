use worker::{Env, Error, Result, Url};

pub(crate) struct Config {
    #[cfg_attr(not(feature = "proxy"), allow(dead_code))]
    pub(crate) user_id: String,
    #[cfg(feature = "dns")]
    pub(crate) dns: crate::dns::DnsService,
}

impl Config {
    #[allow(clippy::single_call_fn)]
    pub(crate) fn from_env(env: &Env, _url: &Url) -> Result<Self> {
        let user_id = uuid::Uuid::parse_str(
            &env.var("UUID")
                .map_err(|_| Error::RustError("UUID is required".into()))?
                .to_string(),
        )
        .map_err(|_| Error::RustError("UUID must be a valid UUID".into()))?
        .to_string();
        Ok(Self {
            #[cfg(feature = "dns")]
            dns: crate::dns::DnsService::new(env, &_url.origin().ascii_serialization(), &user_id)?,
            user_id,
        })
    }
}
