pub(super) const CONNECT_TIMEOUT_MS: u32 = 10_000;

pub(super) fn decode_message(message: worker::MessageEvent) -> Option<Vec<u8>> {
    message
        .bytes()
        .filter(|bytes| !bytes.is_empty())
        .or_else(|| {
            message
                .text()
                .and_then(|text| (!text.is_empty()).then_some(text.into_bytes()))
        })
}
