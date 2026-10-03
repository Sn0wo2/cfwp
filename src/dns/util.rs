use futures_util::StreamExt;
use worker::{ByteStream, Error, Result};

pub(crate) async fn read_body(mut stream: ByteStream, limit: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if chunk.len() > limit.saturating_sub(bytes.len()) {
            return Err(Error::RustError("DNS message too large".into()));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}
