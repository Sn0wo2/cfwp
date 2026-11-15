use std::future::Future;
use std::time::Duration;

use worker::{Delay, Response, Result};

pub(crate) async fn with_timeout<F: Future>(timeout_ms: u32, future: F) -> Option<F::Output> {
    let timer = Delay::from(Duration::from_millis(u64::from(timeout_ms)));
    futures_util::pin_mut!(future, timer);
    match futures_util::future::select(future, timer).await {
        futures_util::future::Either::Left((result, _)) => Some(result),
        futures_util::future::Either::Right(_) => None,
    }
}

pub(crate) fn error(message: &str, status: u16) -> Result<Response> {
    let mut response = Response::error(message, status)?;
    response.headers_mut().set("cache-control", "no-store")?;
    response
        .headers_mut()
        .set("x-content-type-options", "nosniff")?;
    Ok(response)
}
