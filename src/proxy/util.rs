use tokio::io::AsyncWriteExt;
use wasm_bindgen::JsCast;
use worker::{Error, Result, Socket};

use crate::util::with_timeout;

pub(super) async fn open_and_send(
    mut socket: Socket,
    payload: &[u8],
    route: &str,
) -> Result<Socket> {
    match with_timeout(10_000, async {
        socket.opened().await?;
        if !payload.is_empty() {
            socket.write_all(payload).await?;
            socket.flush().await?;
        }
        Ok(())
    })
    .await
    {
        Some(Ok(())) => Ok(socket),
        Some(Err(err)) => {
            drop(socket.close().await);
            Err(err)
        }
        None => {
            drop(socket.close().await);
            Err(Error::RustError(format!(
                "{route} connection timed out after 10000 ms"
            )))
        }
    }
}

pub(super) fn subtle() -> Result<web_sys::SubtleCrypto> {
    js_sys::Reflect::get(&js_sys::global(), &"crypto".into())
        .and_then(JsCast::dyn_into::<web_sys::Crypto>)
        .map(|crypto| crypto.subtle())
        .map_err(|_| Error::RustError("WebCrypto is unavailable".into()))
}

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

pub(super) fn increment_le(bytes: &mut [u8]) {
    for byte in bytes {
        let (sum, overflow) = byte.overflowing_add(1);
        *byte = sum;
        if !overflow {
            return;
        }
    }
}
