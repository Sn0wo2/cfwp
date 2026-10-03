use std::future::Future;
use std::time::Duration;

use futures_util::FutureExt;
use worker::{Delay, Result, Socket};

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

pub(super) async fn with_timeout<F: Future>(timeout_ms: u32, future: F) -> Option<F::Output> {
    let future = future.fuse();
    let timer = Delay::from(Duration::from_millis(u64::from(timeout_ms))).fuse();
    futures_util::pin_mut!(future, timer);
    match futures_util::future::select(future, timer).await {
        futures_util::future::Either::Left((result, _)) => Some(result),
        futures_util::future::Either::Right(((), _)) => None,
    }
}
