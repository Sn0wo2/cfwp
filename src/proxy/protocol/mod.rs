mod shadowsocks;
mod vmess;

use std::cell::RefCell;

use aes::Aes128;
use aes::cipher::{BlockCipherDecrypt, KeyInit as BlockKeyInit};
use chacha20poly1305::aead::Aead;
use hashlink::LinkedHashSet;
use sha2::{Digest, Sha224, Sha256};
use shadowsocks_crypto::v1::openssl_bytes_to_key;
use uuid::Uuid;
use worker::{Error, Result};

use socksaddr::{ParseError, SocksAddr};

use crate::proxy::webcrypto;

const MAX_SEEN_SALTS: usize = 32 * 1024;

thread_local! {
    static SEEN_SALTS: RefCell<LinkedHashSet<(usize, Vec<u8>)>> =
        RefCell::new(LinkedHashSet::new());
}

pub(super) struct InitialRequest {
    pub(super) hostname: String,
    pub(super) port: u16,
    pub(super) is_udp: bool,
    pub(super) payload: Vec<u8>,
    pub(super) codec: Codec,
}

pub(super) enum Decoder {
    Plain,
    Shadowsocks(shadowsocks::ChunkDecoder),
    Vmess(vmess::ChunkDecoder),
}

pub(super) enum Encoder {
    Plain { response_header: Option<Vec<u8>> },
    Shadowsocks(shadowsocks::ChunkEncoder),
    Vmess(vmess::ChunkEncoder),
}

pub(super) struct Codec {
    pub(super) inbound: Decoder,
    pub(super) outbound: Encoder,
}

impl Codec {
    pub(super) const fn plain(response_header: Option<Vec<u8>>) -> Self {
        Self {
            inbound: Decoder::Plain,
            outbound: Encoder::Plain { response_header },
        }
    }
}

impl Decoder {
    pub(super) async fn decode(&mut self, bytes: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::Plain => Ok(bytes.to_vec()),
            Self::Shadowsocks(decoder) => decoder.decode(bytes).await,
            Self::Vmess(decoder) => {
                if decoder.ended && !bytes.is_empty() {
                    return Err(vmess::invalid_at("body data after end marker"));
                }
                decoder.pending.extend_from_slice(bytes);
                let mut pos = 0;
                let decoded = 'decode: {
                    let mut result = Vec::new();
                    loop {
                        if decoder.expected.is_none() {
                            if decoder
                                .pending
                                .get(pos..)
                                .is_none_or(|pending| pending.len() < 2)
                            {
                                break;
                            }
                            let padding =
                                vmess::padding_length(&mut decoder.masker, decoder.options);
                            let mut mask = [0_u8; 2];
                            if let Some(masker) = &mut decoder.masker {
                                masker.read(&mut mask);
                            }
                            let length_end = pos + 2;
                            let Some(length_bytes) = decoder
                                .pending
                                .get(pos..length_end)
                                .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
                            else {
                                break 'decode Err(vmess::invalid_at("invalid body chunk length"));
                            };
                            let length =
                                u16::from_be_bytes(length_bytes) ^ u16::from_be_bytes(mask);
                            pos += 2;
                            if usize::from(length) > vmess::MAX_CHUNK
                                || usize::from(length) < 16 + padding
                            {
                                break 'decode Err(vmess::invalid_at("invalid body chunk length"));
                            }
                            decoder.expected = Some((usize::from(length), padding));
                        }
                        let Some((length, padding)) = decoder.expected else {
                            break 'decode Err(vmess::invalid_at("invalid body chunk length"));
                        };
                        if decoder
                            .pending
                            .get(pos..)
                            .is_none_or(|pending| pending.len() < length)
                        {
                            break;
                        }
                        let nonce = vmess::chunk_nonce(&decoder.iv, decoder.counter);
                        let Some(data) = decoder.pending.get(pos..pos + length - padding) else {
                            break 'decode Err(vmess::invalid_at("invalid body chunk length"));
                        };
                        let payload = match &decoder.cipher {
                            vmess::BodyCipher::Aes(key) => {
                                webcrypto::aes_gcm_decrypt(key, &nonce, None, data)
                                    .await
                                    .map_err(|_| {
                                        vmess::invalid_at("AES body chunk authentication failed")
                                    })
                            }
                            vmess::BodyCipher::ChaCha(cipher) => chacha20poly1305::Nonce::try_from(
                                nonce.as_slice(),
                            )
                            .map_or_else(
                                |_| Err(vmess::invalid_at("invalid encrypted request")),
                                |nonce| {
                                    cipher.decrypt(&nonce, data).map_err(|_| {
                                        vmess::invalid_at("ChaCha body chunk authentication failed")
                                    })
                                },
                            ),
                        }?;
                        let end_marker = length == 16 + padding;
                        if end_marker && !payload.is_empty() {
                            break 'decode Err(vmess::invalid_at("invalid body end marker"));
                        }
                        result.extend(payload);
                        let Some(counter) = decoder.counter.checked_add(1) else {
                            break 'decode Err(vmess::invalid_at("body chunk counter exhausted"));
                        };
                        decoder.counter = counter;
                        pos += length;
                        decoder.expected = None;
                        if end_marker {
                            decoder.ended = true;
                            break;
                        }
                    }
                    Ok(result)
                };
                decoder.pending.drain(..pos);
                decoded.and_then(|result| {
                    if decoder.ended && !decoder.pending.is_empty() {
                        Err(vmess::invalid_at("trailing data after body end marker"))
                    } else {
                        Ok(result)
                    }
                })
            }
        }
    }
}

impl Encoder {
    pub(super) async fn encode(&mut self, bytes: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::Plain { response_header } => {
                let mut result = response_header.take().unwrap_or_default();
                result.extend_from_slice(bytes);
                Ok(result)
            }
            Self::Shadowsocks(encoder) => {
                if bytes.is_empty() {
                    return Ok(Vec::new());
                }
                let tag_len = encoder.cipher.tag_len();
                let mut encrypted = encoder.salt.take().unwrap_or_default();
                encrypted.reserve(
                    bytes.len() + bytes.len().div_ceil(shadowsocks::MAX_CHUNK) * (2 + tag_len * 2),
                );
                for chunk in bytes.chunks(shadowsocks::MAX_CHUNK) {
                    let length = (chunk.len() as u16).to_be_bytes().to_vec();
                    encrypted.extend_from_slice(&encoder.cipher.encrypt(&length).await?);
                    encrypted.extend_from_slice(&encoder.cipher.encrypt(chunk).await?);
                }
                Ok(encrypted)
            }
            Self::Vmess(encoder) => {
                let mut output = encoder.header.take().unwrap_or_default();
                for part in bytes.chunks(vmess::MAX_CHUNK - 16 - 64) {
                    let padding = vmess::padding_length(&mut encoder.masker, encoder.options);
                    let mut mask = [0_u8; 2];
                    if let Some(masker) = &mut encoder.masker {
                        masker.read(&mut mask);
                    }
                    output.extend_from_slice(
                        &(((part.len() + padding + 16) as u16) ^ u16::from_be_bytes(mask))
                            .to_be_bytes(),
                    );
                    let nonce = vmess::chunk_nonce(&encoder.iv, encoder.counter);
                    output.extend(match &encoder.cipher {
                        vmess::BodyCipher::Aes(key) => {
                            webcrypto::aes_gcm_encrypt(key, &nonce, None, part)
                                .await
                                .map_err(|_| vmess::invalid_at("invalid encrypted request"))?
                        }
                        vmess::BodyCipher::ChaCha(cipher) => cipher
                            .encrypt(
                                &chacha20poly1305::Nonce::try_from(nonce.as_slice())
                                    .map_err(|_| vmess::invalid_at("invalid encrypted request"))?,
                                part,
                            )
                            .map_err(|_| vmess::invalid_at("invalid encrypted request"))?,
                    });
                    output.resize(output.len() + padding, 0);
                    encoder.counter = encoder
                        .counter
                        .checked_add(1)
                        .ok_or_else(|| vmess::invalid_at("response chunk counter exhausted"))?;
                }
                Ok(output)
            }
        }
    }
}

impl InitialRequest {
    #[cfg(feature = "dns")]
    pub(super) const fn is_dns_request(&self) -> bool {
        self.is_udp && self.port == 53
    }

    pub(super) fn mux_mode(&self) -> Option<super::mux::MuxMode> {
        match (self.hostname.as_str(), self.port) {
            (super::mux::SING_MUX_HOST, super::mux::SING_MUX_PORT) => {
                Some(super::mux::MuxMode::SingMux)
            }
            (super::mux::MUX_COOL_HOST, super::mux::MUX_COOL_PORT) => {
                Some(super::mux::MuxMode::MuxCool)
            }
            _ => None,
        }
    }

    #[allow(clippy::single_call_fn)]
    pub(super) async fn parse(chunk: &[u8], user_id: &str) -> Result<Option<Self>> {
        if chunk.len() < 16 {
            return Ok(None);
        }
        if chunk.len() >= shadowsocks::MIN_PROBE_HEADER {
            let compact = user_id.replace('-', "");
            for (kind_index, kind) in shadowsocks::KINDS.into_iter().enumerate() {
                let salt_len = kind.salt_len();
                let header_len = salt_len + 2 + kind.tag_len();
                if chunk.len() < header_len {
                    continue;
                }
                let salt_bytes = chunk
                    .get(..salt_len)
                    .ok_or_else(|| Error::RustError("invalid request".into()))?;
                for candidate in [compact.as_str(), user_id]
                    .into_iter()
                    .take(if compact == user_id { 1 } else { 2 })
                {
                    let mut key = vec![0; kind.key_len()];
                    openssl_bytes_to_key(candidate.as_bytes(), &mut key);
                    let mut decoder = shadowsocks::ChunkDecoder {
                        cipher: shadowsocks::Cipher::new(kind, &key, salt_bytes).await?,
                        pending: Vec::new(),
                        expected: None,
                    };
                    let encrypted_address = chunk
                        .get(salt_len..header_len)
                        .ok_or_else(|| Error::RustError("invalid request".into()))?;
                    if decoder.decode(encrypted_address).await.is_err() {
                        continue;
                    }
                    let encrypted_payload = chunk
                        .get(header_len..)
                        .ok_or_else(|| Error::RustError("invalid request".into()))?;
                    let decrypted = decoder.decode(encrypted_payload).await?;
                    let (addr, address_index) = match SocksAddr::parse_socks(&decrypted) {
                        Ok(parsed) => parsed,
                        Err(ParseError::Truncated) => return Ok(None),
                        Err(ParseError::Invalid(message)) => {
                            return Err(Error::RustError(message.into()));
                        }
                    };
                    if matches!(&addr, SocksAddr::Domain(domain, _) if domain.is_empty()) {
                        return Err(Error::RustError("empty Shadowsocks hostname".into()));
                    }
                    if addr.port() == 0 {
                        return Err(Error::RustError("invalid Shadowsocks port".into()));
                    }
                    let salt = (kind_index, salt_bytes.to_vec());
                    SEEN_SALTS.with(|seen| {
                        let mut seen = seen.borrow_mut();
                        if seen.contains(&salt) {
                            return Err(Error::RustError("replayed Shadowsocks salt".into()));
                        }
                        seen.insert(salt);
                        if seen.len() > MAX_SEEN_SALTS {
                            seen.pop_front();
                        }
                        Ok(())
                    })?;
                    acta::info!("protocol: shadowsocks selected");
                    let mut salt = vec![0; kind.salt_len()];
                    getrandom::fill(&mut salt).map_err(|err| {
                        Error::RustError(format!("Shadowsocks salt generation failed: {err}"))
                    })?;
                    return Ok(Some(Self {
                        hostname: addr.host().into_owned(),
                        port: addr.port(),
                        is_udp: false,
                        payload: decrypted
                            .get(address_index..)
                            .ok_or_else(|| Error::RustError("invalid request".into()))?
                            .to_vec(),
                        codec: Codec {
                            inbound: Decoder::Shadowsocks(decoder),
                            outbound: Encoder::Shadowsocks(shadowsocks::ChunkEncoder {
                                cipher: shadowsocks::Cipher::new(kind, &key, &salt).await?,
                                salt: Some(salt),
                            }),
                        },
                    }));
                }
            }
        }

        if let Some(request) = 'vmess: {
            if chunk.len() < 16 {
                break 'vmess None;
            }
            let Ok(uuid) = Uuid::parse_str(user_id) else {
                break 'vmess None;
            };
            let mut seed = uuid.as_bytes().to_vec();
            seed.extend_from_slice(b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
            let cmd_key = md5::compute(seed).0;
            let auth: [u8; 16] = chunk
                .get(..16)
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or_else(|| vmess::invalid_at("invalid encrypted request"))?;
            let mut block = auth.into();
            Aes128::new_from_slice(&vmess::kdf16(&cmd_key, &[b"AES Auth ID Encryption"]))
                .map_err(|_| vmess::invalid_at("invalid encrypted request"))?
                .decrypt_block(&mut block);
            let Some(time_bytes) = block.get(..8).and_then(|bytes| bytes.try_into().ok()) else {
                break 'vmess None;
            };
            let Some(crc_bytes) = block.get(12..16).and_then(|bytes| bytes.try_into().ok()) else {
                break 'vmess None;
            };
            let Some(authenticated) = block.get(..12) else {
                break 'vmess None;
            };
            let time = i64::from_be_bytes(time_bytes);
            if u32::from_be_bytes(crc_bytes) != crc32fast::hash(authenticated)
                || (i128::from(vmess::now()) - i128::from(time)).abs()
                    > i128::from(vmess::CLOCK_SKEW)
            {
                break 'vmess None;
            }
            if chunk.len() < 42 {
                return Ok(None);
            }
            let connection_nonce = chunk
                .get(34..42)
                .ok_or_else(|| vmess::invalid_at("invalid encrypted request"))?;
            let size = u16::from_be_bytes(
                vmess::open(
                    vmess::kdf16(
                        &cmd_key,
                        &[b"VMess Header AEAD Key_Length", &auth, connection_nonce],
                    ),
                    vmess::nonce(
                        &cmd_key,
                        &[b"VMess Header AEAD Nonce_Length", &auth, connection_nonce],
                    ),
                    chunk
                        .get(16..34)
                        .ok_or_else(|| vmess::invalid_at("invalid encrypted request"))?,
                    &auth,
                    "header length authentication failed",
                )
                .await?
                .as_slice()
                .try_into()
                .map_err(|_| vmess::invalid_at("invalid encrypted request"))?,
            ) as usize;
            if !(41..=vmess::MAX_HEADER).contains(&size) {
                return Err(vmess::invalid_at("invalid header length"));
            }
            let total = 42 + size + 16;
            if chunk.len() < total {
                return Ok(None);
            }
            let header = vmess::open(
                vmess::kdf16(
                    &cmd_key,
                    &[b"VMess Header AEAD Key", &auth, connection_nonce],
                ),
                vmess::nonce(
                    &cmd_key,
                    &[b"VMess Header AEAD Nonce", &auth, connection_nonce],
                ),
                chunk
                    .get(42..total)
                    .ok_or_else(|| vmess::invalid_at("invalid encrypted request"))?,
                &auth,
                "header authentication failed",
            )
            .await?;
            if header.len() != size || header.first() != Some(&1) {
                return Err(vmess::invalid_at("invalid header version or size"));
            }
            let mut iv = [0_u8; 16];
            let mut key = [0_u8; 16];
            iv.copy_from_slice(
                header
                    .get(1..17)
                    .ok_or_else(|| vmess::invalid_at("invalid encrypted request"))?,
            );
            key.copy_from_slice(
                header
                    .get(17..33)
                    .ok_or_else(|| vmess::invalid_at("invalid encrypted request"))?,
            );
            let option = header
                .get(34)
                .copied()
                .ok_or_else(|| vmess::invalid_at("invalid encrypted request"))?;
            let security_padding = header
                .get(35)
                .copied()
                .ok_or_else(|| vmess::invalid_at("invalid encrypted request"))?;
            let security = security_padding & 0x0f;
            let command = header
                .get(37)
                .copied()
                .ok_or_else(|| vmess::invalid_at("invalid encrypted request"))?;
            let mux_cool = command == 3;
            if !matches!(security, 3 | 4)
                || header.get(36) != Some(&0)
                || !(command == 1 || mux_cool)
                || option & !0x0d != 0
                || option & 0x01 == 0
                || (option & 0x08 != 0 && option & 0x04 == 0)
            {
                acta::error!("vmess: unsupported command, security, or options");
                return Err(Error::RustError("unsupported encrypted stream mode".into()));
            }
            let (hostname, port, index) = if mux_cool {
                (
                    super::mux::MUX_COOL_HOST.to_string(),
                    super::mux::MUX_COOL_PORT,
                    38,
                )
            } else {
                let address = header
                    .get(38..)
                    .ok_or_else(|| vmess::invalid_at("invalid request address"))?;
                let (addr, consumed) = SocksAddr::parse_xray(address)
                    .map_err(|_| vmess::invalid_at("invalid request address"))?;
                (addr.host().into_owned(), addr.port(), 38 + consumed)
            };
            if index + usize::from(security_padding >> 4) + 4 != size {
                return Err(vmess::invalid_at("invalid header padding"));
            }
            let checksum_start = size - 4;
            let checksum_input = header
                .get(..checksum_start)
                .ok_or_else(|| vmess::invalid_at("invalid encrypted request"))?;
            let checksum = header
                .get(checksum_start..)
                .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
                .ok_or_else(|| vmess::invalid_at("invalid encrypted request"))?;
            if checksum_input.iter().fold(0x811c_9dc5_u32, |hash, byte| {
                (hash ^ u32::from(*byte)).wrapping_mul(0x0100_0193)
            }) != u32::from_be_bytes(checksum)
            {
                return Err(vmess::invalid_at("header checksum mismatch"));
            }
            vmess::SEEN_AUTH_IDS.with(|seen| {
                let mut seen = seen.borrow_mut();
                let current = vmess::now();
                if seen
                    .get(&auth)
                    .is_some_and(|expires_at| *expires_at >= current)
                {
                    return Err(vmess::invalid_at("replayed authentication ID"));
                }
                if seen.len() >= 32 * 1024 {
                    seen.retain(|_, expires_at| *expires_at >= current);
                    if seen.len() >= 32 * 1024 {
                        return Err(vmess::invalid_at("authentication replay cache full"));
                    }
                }
                seen.insert(auth, time.saturating_add(vmess::CLOCK_SKEW));
                Ok(())
            })?;
            acta::info!("vmess: request header authenticated");
            let response_key: [u8; 16] = Sha256::digest(key)
                .get(..16)
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or_else(|| vmess::invalid_at("invalid encrypted request"))?;
            let response_iv: [u8; 16] = Sha256::digest(iv)
                .get(..16)
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or_else(|| vmess::invalid_at("invalid encrypted request"))?;
            let mut response = vmess::seal(
                vmess::kdf16(&response_key, &[b"AEAD Resp Header Len Key"]),
                vmess::nonce(&response_iv, &[b"AEAD Resp Header Len IV"]),
                &4_u16.to_be_bytes(),
            )
            .await?;
            response.extend(
                vmess::seal(
                    vmess::kdf16(&response_key, &[b"AEAD Resp Header Key"]),
                    vmess::nonce(&response_iv, &[b"AEAD Resp Header IV"]),
                    &[
                        header
                            .get(33)
                            .copied()
                            .ok_or_else(|| vmess::invalid_at("invalid encrypted request"))?,
                        0,
                        0,
                        0,
                    ],
                )
                .await?,
            );
            let mut request = Self {
                hostname,
                port,
                is_udp: false,
                payload: Vec::new(),
                codec: Codec {
                    inbound: Decoder::Vmess(vmess::ChunkDecoder {
                        cipher: vmess::body_cipher(key, security).await?,
                        iv,
                        options: option,
                        masker: vmess::masker(&iv, option),
                        counter: 0,
                        pending: Vec::new(),
                        expected: None,
                        ended: false,
                    }),
                    outbound: Encoder::Vmess(vmess::ChunkEncoder {
                        cipher: vmess::body_cipher(response_key, security).await?,
                        iv: response_iv,
                        options: option,
                        masker: vmess::masker(&response_iv, option),
                        counter: 0,
                        header: Some(response),
                    }),
                },
            };
            request.payload = request
                .codec
                .inbound
                .decode(
                    chunk
                        .get(total..)
                        .ok_or_else(|| vmess::invalid_at("invalid encrypted request"))?,
                )
                .await?;
            break 'vmess Some(request);
        } {
            acta::info!("protocol: vmess selected");
            return Ok(Some(request));
        }

        let is_vless = chunk.get(..17).is_some_and(|header| {
            header.first() == Some(&0)
                && Uuid::parse_str(user_id)
                    .is_ok_and(|id| header.get(1..17) == Some(id.as_bytes().as_slice()))
        });
        if is_vless {
            acta::info!("protocol: vless selected");
            if chunk.len() < 19 {
                return Ok(None);
            }
            let version = chunk
                .first()
                .copied()
                .ok_or_else(|| Error::RustError("invalid VLESS header".into()))?;
            if version > 1 {
                return Err(Error::RustError("unsupported VLESS version".into()));
            }
            let opt_len = usize::from(
                chunk
                    .get(17)
                    .copied()
                    .ok_or_else(|| Error::RustError("invalid VLESS header".into()))?,
            );
            if opt_len != 0 {
                return Err(Error::RustError("unsupported VLESS addons".into()));
            }
            let cmd_index = 18 + opt_len;
            if chunk.len() < cmd_index + 4 {
                return Ok(None);
            }
            let command = chunk
                .get(cmd_index)
                .copied()
                .ok_or_else(|| Error::RustError("invalid VLESS header".into()))?;
            if !matches!(command, 1..=3) {
                return Err(Error::RustError("unsupported route mode".into()));
            }
            if command == 3 {
                acta::info!(
                    "protocol: vless mux.cool session (payload={}B)",
                    chunk.len() - cmd_index - 1
                );
                return Ok(Some(Self {
                    hostname: super::mux::MUX_COOL_HOST.to_string(),
                    port: super::mux::MUX_COOL_PORT,
                    is_udp: false,
                    payload: chunk
                        .get(cmd_index + 1..)
                        .ok_or_else(|| Error::RustError("invalid VLESS header".into()))?
                        .to_vec(),
                    codec: Codec::plain(Some(vec![version, 0])),
                }));
            }
            let is_udp = command == 2;
            let address_start = cmd_index + 1;
            let address_bytes = chunk
                .get(address_start..)
                .ok_or_else(|| Error::RustError("invalid VLESS header".into()))?;
            let (addr, addr_len) = match SocksAddr::parse_xray(address_bytes) {
                Ok(parsed) => parsed,
                Err(ParseError::Truncated) => return Ok(None),
                Err(ParseError::Invalid(message)) => {
                    return Err(Error::RustError(message.into()));
                }
            };
            let payload = chunk
                .get(address_start + addr_len..)
                .ok_or_else(|| Error::RustError("invalid VLESS header".into()))?
                .to_vec();
            acta::info!(
                "identity-header parsed: rev={} opt={} mode={} route={addr} datagram={} payload={}B",
                version,
                opt_len,
                command,
                is_udp,
                payload.len()
            );
            return Ok(Some(Self {
                hostname: addr.host().into_owned(),
                port: addr.port(),
                is_udp,
                payload,
                codec: Codec::plain(Some(vec![version, 0])),
            }));
        }
        if chunk
            .get(..16)
            .is_some_and(|auth| auth.iter().all(u8::is_ascii_hexdigit))
        {
            acta::info!("protocol: trojan selected");
            acta::info!("trojan: received header candidate ({} bytes)", chunk.len());
            if chunk.len() < 60 {
                acta::info!("trojan: waiting for header");
                return Ok(None);
            }
            if chunk.get(56..58) != Some(b"\r\n") {
                acta::error!("trojan: invalid authentication delimiter");
                return Err(Error::RustError("invalid request header".into()));
            }
            let provided = std::str::from_utf8(
                chunk
                    .get(..56)
                    .ok_or_else(|| Error::RustError("invalid access token".into()))?,
            )
            .map_err(|_| Error::RustError("invalid access token".into()))?;
            if provided != hex::encode(Sha224::digest(user_id.as_bytes()))
                && provided != hex::encode(Sha224::digest(user_id.replace('-', "").as_bytes()))
            {
                acta::error!("trojan: authentication failed");
                return Err(Error::RustError("invalid access token".into()));
            }
            acta::info!("trojan: authenticated");

            let socks = chunk
                .get(58..)
                .ok_or_else(|| Error::RustError("invalid request header".into()))?;
            let command = socks
                .first()
                .copied()
                .ok_or_else(|| Error::RustError("invalid request header".into()))?;
            if command != 1 {
                acta::error!("trojan: unsupported command {command}");
                return Err(Error::RustError("unsupported stream mode".into()));
            }
            let (addr, address_end) = match SocksAddr::parse_socks(socks) {
                Ok(parsed) => parsed,
                Err(ParseError::Truncated) => {
                    acta::info!("trojan: waiting for route header");
                    return Ok(None);
                }
                Err(ParseError::Invalid(message)) => {
                    return Err(Error::RustError(message.into()));
                }
            };
            let delimiter_end = address_end
                .checked_add(2)
                .ok_or_else(|| Error::RustError("invalid request header".into()))?;
            if socks.len() < delimiter_end {
                acta::info!("trojan: waiting for route header");
                return Ok(None);
            }
            if socks.get(address_end..delimiter_end) != Some(b"\r\n") {
                acta::error!("trojan: invalid route delimiter");
                return Err(Error::RustError("invalid frame delimiter".into()));
            }
            let payload = socks
                .get(delimiter_end..)
                .ok_or_else(|| Error::RustError("invalid request header".into()))?
                .to_vec();
            acta::info!(
                "trojan: request parsed (addr={addr}, payload={} bytes)",
                payload.len()
            );
            return Ok(Some(Self {
                hostname: addr.host().into_owned(),
                port: addr.port(),
                is_udp: false,
                payload,
                codec: Codec::plain(None),
            }));
        }
        if chunk.len() < shadowsocks::MAX_PROBE_HEADER {
            return Ok(None);
        }
        acta::info!("protocol: no matching request format");
        Err(Error::RustError("invalid request".into()))
    }
}
