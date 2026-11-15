use std::borrow::Cow;

use hkdf::Hkdf;
use sha1::Sha1;
use shadowsocks_crypto::CipherKind;
use web_sys::CryptoKey;
use worker::{Error, Result};

use crate::proxy::{util::increment_le, webcrypto};

pub(in crate::proxy) enum Cipher {
    Soft(shadowsocks_crypto::v1::Cipher),
    Web {
        key: CryptoKey,
        nonce: [u8; 12],
        tag_len: usize,
    },
}

impl Cipher {
    pub(in crate::proxy) async fn new(kind: CipherKind, key: &[u8], salt: &[u8]) -> Result<Self> {
        if !matches!(kind, CipherKind::AES_128_GCM | CipherKind::AES_256_GCM) {
            return Ok(Self::Soft(shadowsocks_crypto::v1::Cipher::new(
                kind, key, salt,
            )));
        }
        let mut subkey = vec![0_u8; key.len()];
        Hkdf::<Sha1>::new(Some(salt), key)
            .expand(b"ss-subkey", &mut subkey)
            .map_err(|_| Error::RustError("invalid Shadowsocks key length".into()))?;
        Ok(Self::Web {
            key: webcrypto::import_aes_gcm_key(&subkey).await?,
            nonce: [0; 12],
            tag_len: kind.tag_len(),
        })
    }

    pub(super) fn tag_len(&self) -> usize {
        match self {
            Self::Soft(cipher) => cipher.tag_len(),
            Self::Web { tag_len, .. } => *tag_len,
        }
    }
    pub(super) async fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::Soft(cipher) => {
                let mut pkt = vec![0; plaintext.len() + cipher.tag_len()];
                pkt.get_mut(..plaintext.len())
                    .ok_or_else(|| Error::RustError("invalid Shadowsocks packet length".into()))?
                    .copy_from_slice(plaintext);
                cipher.encrypt_packet(&mut pkt);
                Ok(pkt)
            }
            Self::Web { key, nonce, .. } => {
                let packet = webcrypto::aes_gcm(key, nonce, None, plaintext, true).await?;
                increment_le(nonce);
                Ok(packet)
            }
        }
    }
    pub(super) async fn decrypt(&mut self, packet: &[u8]) -> Option<Vec<u8>> {
        match self {
            Self::Soft(cipher) => {
                let mut pkt = packet.to_vec();
                let tag_len = cipher.tag_len();
                cipher.decrypt_packet(&mut pkt).then(|| {
                    pkt.truncate(pkt.len() - tag_len);
                    pkt
                })
            }
            Self::Web { key, nonce, .. } => {
                let plaintext = webcrypto::aes_gcm(key, nonce, None, packet, false)
                    .await
                    .ok();
                increment_le(nonce);
                plaintext
            }
        }
    }
}
pub(in crate::proxy) struct ChunkDecoder {
    pub(in crate::proxy) cipher: Cipher,
    pub(in crate::proxy) pending: Vec<u8>,
    pub(in crate::proxy) expected: Option<usize>,
}

impl ChunkDecoder {
    pub(in crate::proxy) async fn decode<'a>(&mut self, bytes: &'a [u8]) -> Result<Cow<'a, [u8]>> {
        self.pending.extend_from_slice(bytes);
        let mut plaintext = Vec::new();
        let mut pos = 0;
        let tag_len = self.cipher.tag_len();
        loop {
            let Some(size) = self.expected else {
                if self
                    .pending
                    .get(pos..)
                    .is_none_or(|pending| pending.len() < 2 + tag_len)
                {
                    break;
                }
                let length_end = pos + 2 + tag_len;
                let length_packet = self
                    .pending
                    .get(pos..length_end)
                    .ok_or_else(|| Error::RustError("invalid Shadowsocks chunk length".into()))?;
                let Some(size_bytes) = self.cipher.decrypt(length_packet).await else {
                    return Err(Error::RustError("invalid Shadowsocks chunk length".into()));
                };
                let size_bytes = size_bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::RustError("invalid Shadowsocks chunk length".into()))?;
                let size = usize::from(u16::from_be_bytes(size_bytes));
                if size > 0x3fff {
                    return Err(Error::RustError("Shadowsocks chunk too large".into()));
                }
                pos += 2 + tag_len;
                self.expected = Some(size);
                continue;
            };
            if self
                .pending
                .get(pos..)
                .is_none_or(|pending| pending.len() < size + tag_len)
            {
                break;
            }
            let chunk_end = pos + size + tag_len;
            let encrypted_chunk = self
                .pending
                .get(pos..chunk_end)
                .ok_or_else(|| Error::RustError("invalid Shadowsocks chunk".into()))?;
            let Some(chunk) = self.cipher.decrypt(encrypted_chunk).await else {
                return Err(Error::RustError("invalid Shadowsocks chunk".into()));
            };
            plaintext.extend_from_slice(&chunk);
            pos += size + tag_len;
            self.expected = None;
        }
        self.pending.drain(..pos);
        Ok(Cow::Owned(plaintext))
    }
}

pub(in crate::proxy) struct ChunkEncoder {
    pub(in crate::proxy) cipher: Cipher,
    pub(in crate::proxy) salt: Option<Vec<u8>>,
}

impl ChunkEncoder {
    pub(in crate::proxy) async fn encode<'a>(&mut self, bytes: &'a [u8]) -> Result<Cow<'a, [u8]>> {
        if bytes.is_empty() {
            return Ok(Cow::Borrowed(bytes));
        }
        let tag_len = self.cipher.tag_len();
        let mut encrypted = self.salt.take().unwrap_or_default();
        encrypted.reserve(bytes.len() + bytes.len().div_ceil(0x3fff) * (2 + tag_len * 2));
        for chunk in bytes.chunks(0x3fff) {
            encrypted.extend_from_slice(
                &self
                    .cipher
                    .encrypt(&(chunk.len() as u16).to_be_bytes())
                    .await?,
            );
            encrypted.extend_from_slice(&self.cipher.encrypt(chunk).await?);
        }
        Ok(Cow::Owned(encrypted))
    }
}
