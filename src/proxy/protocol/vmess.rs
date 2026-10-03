use std::cell::RefCell;
use std::collections::HashMap;

use chacha20poly1305::ChaCha20Poly1305;
use chacha20poly1305::KeyInit;
use sha2::{Digest, Sha256};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use shake::Shake128;
use web_sys::CryptoKey;
use worker::{Error, Result};

use crate::proxy::webcrypto;

pub(super) const MAX_HEADER: usize = 4096;
pub(super) const MAX_CHUNK: usize = 16 * 1024;
pub(super) const CLOCK_SKEW: i64 = 120;

thread_local! {
    pub(super) static SEEN_AUTH_IDS: RefCell<HashMap<[u8; 16], i64>> = RefCell::new(HashMap::new());
}

pub(super) fn invalid_at(stage: &str) -> Error {
    acta::error!("vmess: {stage}");
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
    let digest = kdf(key, path);
    let mut result = [0_u8; 16];
    for (destination, source) in result.iter_mut().zip(digest.iter()) {
        *destination = *source;
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
    webcrypto::aes_gcm_decrypt(&cipher, &nonce, Some(aad), data)
        .await
        .map_err(|_| invalid_at(stage))
}

pub(super) async fn seal(key: [u8; 16], nonce: [u8; 12], data: &[u8]) -> Result<Vec<u8>> {
    let cipher = webcrypto::import_aes_gcm_key(&key).await?;
    webcrypto::aes_gcm_encrypt(&cipher, &nonce, None, data).await
}

pub(super) fn nonce(key: &[u8], path: &[&[u8]]) -> [u8; 12] {
    let digest = kdf(key, path);
    let mut result = [0_u8; 12];
    for (destination, source) in result.iter_mut().zip(digest.iter()) {
        *destination = *source;
    }
    result
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

pub(super) fn masker(iv: &[u8; 16], options: u8) -> Option<Box<dyn XofReader>> {
    (options & 0x04 != 0).then(|| {
        let mut shake = Shake128::default();
        shake.update(iv);
        let reader: Box<dyn XofReader> = Box::new(shake.finalize_xof());
        reader
    })
}

pub(super) fn padding_length(masker: &mut Option<Box<dyn XofReader>>, options: u8) -> usize {
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

#[allow(variant_size_differences)]
pub(super) enum BodyCipher {
    Aes(CryptoKey),
    ChaCha(ChaCha20Poly1305),
}

pub(super) async fn body_cipher(key: [u8; 16], security: u8) -> Result<BodyCipher> {
    if security == 3 {
        Ok(BodyCipher::Aes(webcrypto::import_aes_gcm_key(&key).await?))
    } else {
        let first = md5::compute(key).0;
        let mut expanded = [0_u8; 32];
        expanded[..16].copy_from_slice(&first);
        expanded[16..].copy_from_slice(&md5::compute(first).0);
        Ok(BodyCipher::ChaCha(
            ChaCha20Poly1305::new_from_slice(&expanded)
                .map_err(|_| Error::RustError("invalid encrypted request".into()))?,
        ))
    }
}

pub(in crate::proxy) struct ChunkDecoder {
    pub(super) cipher: BodyCipher,
    pub(super) iv: [u8; 16],
    pub(super) options: u8,
    pub(super) masker: Option<Box<dyn XofReader>>,
    pub(super) counter: u16,
    pub(super) pending: Vec<u8>,
    pub(super) expected: Option<(usize, usize)>,
    pub(super) ended: bool,
}

pub(in crate::proxy) struct ChunkEncoder {
    pub(super) cipher: BodyCipher,
    pub(super) iv: [u8; 16],
    pub(super) options: u8,
    pub(super) masker: Option<Box<dyn XofReader>>,
    pub(super) counter: u16,
    pub(super) header: Option<Vec<u8>>,
}
