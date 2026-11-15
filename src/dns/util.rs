use futures_util::StreamExt;
use worker::ByteStream;

use super::{DnsError, DnsResult};

pub(crate) const DNS_MESSAGE_TYPE: &str = "application/dns-message";

pub(crate) fn is_dns_message_type(content_type: &str) -> bool {
    content_type
        .split(';')
        .next()
        .is_some_and(|value| value.trim().eq_ignore_ascii_case(DNS_MESSAGE_TYPE))
}

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
