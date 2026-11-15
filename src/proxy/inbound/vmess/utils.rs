use sha2::{Digest, Sha256};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use shake::{Shake128, Shake128Reader};
use worker::{Error, Result};

use crate::proxy::webcrypto;

pub(super) const MAX_HEADER: usize = 4096;
pub(super) const MAX_CHUNK: usize = 16 * 1024;
pub(super) const CLOCK_SKEW: i64 = 120;

pub(super) fn invalid_at(stage: &str) -> Error {
    tracing::error!("vmess: {stage}");
    Error::RustError("invalid encrypted request".into())
}

fn kdf(key: &[u8], path: &[&[u8]]) -> [u8; 32] {
    fn nested_hmac(keys: &[&[u8]], message: &[u8]) -> [u8; 32] {
        let Some((last, rest)) = keys.split_last() else {
            return Sha256::digest(message).into();
        };
        let mut key = [0_u8; 64];
        if last.len() > 64 {
            for (destination, source) in key.iter_mut().take(32).zip(nested_hmac(rest, last)) {
                *destination = source;
            }
        } else {
            for (destination, source) in key.iter_mut().zip(last.iter()) {
                *destination = *source;
            }
        }
        let mut inner = Vec::with_capacity(64 + message.len());
        inner.extend(key.iter().map(|byte| byte ^ 0x36));
        inner.extend_from_slice(message);
        let mut outer = Vec::with_capacity(96);
        outer.extend(key.iter().map(|byte| byte ^ 0x5c));
        outer.extend_from_slice(&nested_hmac(rest, &inner));
        nested_hmac(rest, &outer)
    }
    let mut keys: Vec<&[u8]> = vec![b"VMess AEAD KDF"];
    keys.extend_from_slice(path);
    nested_hmac(&keys, key)
}

pub(super) fn kdf16(key: &[u8], path: &[&[u8]]) -> [u8; 16] {
    let mut result = [0_u8; 16];
    for (destination, source) in result.iter_mut().zip(kdf(key, path)) {
        *destination = source;
    }
    result
}

pub(super) fn nonce(key: &[u8], path: &[&[u8]]) -> [u8; 12] {
    let mut result = [0_u8; 12];
    for (destination, source) in result.iter_mut().zip(kdf(key, path)) {
        *destination = source;
    }
    result
}

pub(super) async fn open(
    key: [u8; 16],
    nonce: [u8; 12],
    data: &[u8],
    aad: &[u8],
    stage: &str,
) -> Result<Vec<u8>> {
    let cipher = webcrypto::import_aes_gcm_key(&key).await?;
    webcrypto::aes_gcm(&cipher, &nonce, Some(aad), data, false)
        .await
        .map_err(|_| invalid_at(stage))
}

pub(super) async fn seal(key: [u8; 16], nonce: [u8; 12], data: &[u8]) -> Result<Vec<u8>> {
    let cipher = webcrypto::import_aes_gcm_key(&key).await?;
    webcrypto::aes_gcm(&cipher, &nonce, None, data, true).await
}

#[allow(clippy::cast_sign_loss)]
pub(super) fn now() -> i64 {
    #[cfg(target_arch = "wasm32")]
    {
        std::time::Duration::from_millis(js_sys::Date::now() as u64).as_secs() as i64
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64
    }
}

pub(super) fn chunk_nonce(iv: &[u8; 16], counter: u16) -> [u8; 12] {
    let mut nonce = [0_u8; 12];
    nonce[..2].copy_from_slice(&counter.to_be_bytes());
    nonce[2..].copy_from_slice(&iv[2..12]);
    nonce
}

pub(super) fn masker(iv: &[u8; 16], options: u8) -> Option<Shake128Reader> {
    if options & 0x04 == 0 {
        return None;
    }
    Some({
        let mut shake = Shake128::default();
        shake.update(iv);
        shake.finalize_xof()
    })
}

pub(super) fn padding_length(masker: &mut Option<Shake128Reader>, options: u8) -> usize {
    if options & 0x08 != 0 {
        let mut mask = [0_u8; 2];
        if let Some(masker) = masker {
            masker.read(&mut mask);
        }
        (u16::from_be_bytes(mask) % 64) as usize
    } else {
        0
    }
}
