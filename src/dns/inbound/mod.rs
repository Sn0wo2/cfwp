#![allow(clippy::single_call_fn)]

pub(crate) mod https;
pub(crate) mod ws;

use super::config::DnsConfig;

#[derive(Clone)]
pub(crate) struct Config {
    pub(crate) https: https::Config,
    pub(crate) ws: ws::Config,
}

impl Config {
    pub(crate) const fn new(config: &DnsConfig) -> Self {
        Self {
            https: https::Config::new(config),
            ws: ws::Config::new(config),
        }
    }
}
