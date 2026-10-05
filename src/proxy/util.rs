use worker::{Result, Socket};

#[derive(Clone, Debug)]
pub(super) struct SocketTarget {
    pub(super) host: String,
    pub(super) port: u16,
    pub(super) has_explicit_port: bool,
}

pub(super) fn split_multi_value(value: &str) -> Vec<String> {
    value
        .split([',', '\n'])
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect()
}

pub(super) const CONNECT_TIMEOUT_MS: u32 = 10_000;

pub(super) fn connect_tcp(hostname: &str, port: u16) -> Result<Socket> {
    Socket::builder().connect(hostname.to_string(), port)
}
