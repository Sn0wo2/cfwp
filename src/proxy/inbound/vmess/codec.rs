use std::borrow::Cow;

use chacha20poly1305::ChaCha20Poly1305;
use chacha20poly1305::KeyInit;
use chacha20poly1305::aead::Aead;
use sha3::digest::XofReader;
use shake::Shake128Reader;
use web_sys::CryptoKey;
use worker::{Error, Result};

use super::utils::{MAX_CHUNK, chunk_nonce, invalid_at, padding_length};
use crate::proxy::webcrypto;

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
    pub(super) masker: Option<Shake128Reader>,
    pub(super) counter: u16,
    pub(super) pending: Vec<u8>,
    pub(super) expected: Option<(usize, usize)>,
    pub(super) ended: bool,
}

pub(in crate::proxy) struct ChunkEncoder {
    pub(super) cipher: BodyCipher,
    pub(super) iv: [u8; 16],
    pub(super) options: u8,
    pub(super) masker: Option<Shake128Reader>,
    pub(super) counter: u16,
    pub(super) header: Option<Vec<u8>>,
}

impl ChunkDecoder {
    pub(in crate::proxy) async fn decode<'a>(&mut self, bytes: &'a [u8]) -> Result<Cow<'a, [u8]>> {
        if self.ended && !bytes.is_empty() {
            return Err(invalid_at("body data after end marker"));
        }
        self.pending.extend_from_slice(bytes);
        let mut pos = 0;
        let decoded = 'decode: {
            let mut result = Vec::new();
            loop {
                let Some((length, padding)) = self.expected else {
                    if self
                        .pending
                        .get(pos..)
                        .is_none_or(|pending| pending.len() < 2)
                    {
                        break;
                    }
                    let padding = padding_length(&mut self.masker, self.options);
                    let mut mask = [0_u8; 2];
                    if let Some(masker) = &mut self.masker {
                        masker.read(&mut mask);
                    }
                    let Some(length_bytes) = self
                        .pending
                        .get(pos..pos + 2)
                        .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
                    else {
                        break 'decode Err(invalid_at("invalid body chunk length"));
                    };
                    let length = u16::from_be_bytes(length_bytes) ^ u16::from_be_bytes(mask);
                    pos += 2;
                    if usize::from(length) > MAX_CHUNK || usize::from(length) < 16 + padding {
                        break 'decode Err(invalid_at("invalid body chunk length"));
                    }
                    self.expected = Some((usize::from(length), padding));
                    continue;
                };
                if self
                    .pending
                    .get(pos..)
                    .is_none_or(|pending| pending.len() < length)
                {
                    break;
                }
                let nonce = chunk_nonce(&self.iv, self.counter);
                let Some(data) = self.pending.get(pos..pos + length - padding) else {
                    break 'decode Err(invalid_at("invalid body chunk length"));
                };
                let payload = match &self.cipher {
                    BodyCipher::Aes(key) => webcrypto::aes_gcm(key, &nonce, None, data, false)
                        .await
                        .map_err(|_| invalid_at("AES body chunk authentication failed")),
                    BodyCipher::ChaCha(cipher) => {
                        chacha20poly1305::Nonce::try_from(nonce.as_slice()).map_or_else(
                            |_| Err(invalid_at("invalid encrypted request")),
                            |nonce| {
                                cipher.decrypt(&nonce, data).map_err(|_| {
                                    invalid_at("ChaCha body chunk authentication failed")
                                })
                            },
                        )
                    }
                }?;
                let end_marker = length == 16 + padding;
                if end_marker && !payload.is_empty() {
                    break 'decode Err(invalid_at("invalid body end marker"));
                }
                result.extend(payload);
                let Some(counter) = self.counter.checked_add(1) else {
                    break 'decode Err(invalid_at("body chunk counter exhausted"));
                };
                self.counter = counter;
                pos += length;
                self.expected = None;
                if end_marker {
                    self.ended = true;
                    break;
                }
            }
            Ok(Cow::Owned(result))
        };
        self.pending.drain(..pos);
        decoded.and_then(|result| {
            if self.ended && !self.pending.is_empty() {
                Err(invalid_at("trailing data after body end marker"))
            } else {
                Ok(result)
            }
        })
    }
}

impl ChunkEncoder {
    pub(in crate::proxy) async fn encode<'a>(&mut self, bytes: &'a [u8]) -> Result<Cow<'a, [u8]>> {
        let mut output = self.header.take().unwrap_or_default();
        for part in bytes.chunks(MAX_CHUNK - 16 - 64) {
            let padding = padding_length(&mut self.masker, self.options);
            let mut mask = [0_u8; 2];
            if let Some(masker) = &mut self.masker {
                masker.read(&mut mask);
            }
            output.extend_from_slice(
                &(((part.len() + padding + 16) as u16) ^ u16::from_be_bytes(mask)).to_be_bytes(),
            );
            let nonce = chunk_nonce(&self.iv, self.counter);
            output.extend(match &self.cipher {
                BodyCipher::Aes(key) => webcrypto::aes_gcm(key, &nonce, None, part, true)
                    .await
                    .map_err(|_| invalid_at("invalid encrypted request"))?,
                BodyCipher::ChaCha(cipher) => cipher
                    .encrypt(
                        &chacha20poly1305::Nonce::try_from(nonce.as_slice())
                            .map_err(|_| invalid_at("invalid encrypted request"))?,
                        part,
                    )
                    .map_err(|_| invalid_at("invalid encrypted request"))?,
            });
            output.resize(output.len() + padding, 0);
            self.counter = self
                .counter
                .checked_add(1)
                .ok_or_else(|| invalid_at("response chunk counter exhausted"))?;
        }
        Ok(Cow::Owned(output))
    }
}
