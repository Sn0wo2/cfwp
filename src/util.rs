use std::future::Future;
use std::time::Duration;

use futures_util::FutureExt;
use worker::Delay;

pub(crate) async fn with_timeout<F: Future>(timeout_ms: u32, future: F) -> Option<F::Output> {
    let future = future.fuse();
    let timer = Delay::from(Duration::from_millis(u64::from(timeout_ms))).fuse();
    futures_util::pin_mut!(future, timer);
    match futures_util::future::select(future, timer).await {
        futures_util::future::Either::Left((result, _)) => Some(result),
        futures_util::future::Either::Right(((), _)) => None,
    }
}
