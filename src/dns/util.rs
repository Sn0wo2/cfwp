use futures_util::StreamExt;
use worker::ByteStream;

use super::{DnsError, DnsResult};

pub(crate) async fn read_body(mut stream: ByteStream, limit: usize) -> DnsResult<Vec<u8>> {
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if chunk.len() > limit.saturating_sub(bytes.len()) {
            return Err(DnsError::TooLarge);
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}
