use hkdf::Hkdf;
use sha1::Sha1;
use shadowsocks_crypto::CipherKind;
use web_sys::CryptoKey;
use worker::{Error, Result};

use crate::proxy::webcrypto;

pub(super) const MAX_CHUNK: usize = 0x3fff;
pub(super) const KINDS: [CipherKind; 3] = [
    CipherKind::AES_128_GCM,
    CipherKind::AES_256_GCM,
    CipherKind::CHACHA20_POLY1305,
];
pub(super) const MIN_PROBE_HEADER: usize = 16 + 2 + 16;
pub(super) const MAX_PROBE_HEADER: usize = 32 + 2 + 16;
pub(super) enum Cipher {
    Soft(shadowsocks_crypto::v1::Cipher),
    Web {
        key: CryptoKey,
        nonce: [u8; 12],
        tag_len: usize,
    },
}

impl Cipher {
    pub(super) async fn new(kind: CipherKind, key: &[u8], salt: &[u8]) -> Result<Self> {
        if !matches!(kind, CipherKind::AES_128_GCM | CipherKind::AES_256_GCM) {
            return Ok(Self::Soft(shadowsocks_crypto::v1::Cipher::new(
                kind, key, salt,
            )));
        }
        let hk = Hkdf::<Sha1>::new(Some(salt), key);
        let mut subkey = vec![0_u8; key.len()];
        hk.expand(b"ss-subkey", &mut subkey)
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
                let packet = webcrypto::aes_gcm_encrypt(key, nonce, None, plaintext).await?;
                increase_nonce(nonce);
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
                let plaintext = webcrypto::aes_gcm_decrypt(key, nonce, None, packet)
                    .await
                    .ok();
                increase_nonce(nonce);
                plaintext
            }
        }
    }
}
fn increase_nonce(nonce: &mut [u8; 12]) {
    for byte in nonce.iter_mut() {
        let (sum, overflow) = byte.overflowing_add(1);
        *byte = sum;
        if !overflow {
            return;
        }
    }
}

pub(in crate::proxy) struct ChunkDecoder {
    pub(super) cipher: Cipher,
    pub(super) pending: Vec<u8>,
    pub(super) expected: Option<usize>,
}

impl ChunkDecoder {
    pub(super) async fn decode(&mut self, bytes: &[u8]) -> Result<Vec<u8>> {
        self.pending.extend_from_slice(bytes);
        let mut plaintext = Vec::new();
        let mut pos = 0;
        let tag_len = self.cipher.tag_len();
        loop {
            if self.expected.is_none() {
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
                let size_bytes: [u8; 2] = size_bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::RustError("invalid Shadowsocks chunk length".into()))?;
                let size = usize::from(u16::from_be_bytes(size_bytes));
                if size > MAX_CHUNK {
                    return Err(Error::RustError("Shadowsocks chunk too large".into()));
                }
                pos += 2 + tag_len;
                self.expected = Some(size);
            }
            let Some(size) = self.expected else {
                return Err(Error::RustError("invalid Shadowsocks chunk length".into()));
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
        Ok(plaintext)
    }
}

pub(in crate::proxy) struct ChunkEncoder {
    pub(super) cipher: Cipher,
    pub(super) salt: Option<Vec<u8>>,
}
