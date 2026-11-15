use std::cell::RefCell;
use std::collections::HashMap;

use aes::Aes128;
use aes::cipher::{BlockCipherDecrypt, KeyInit as BlockKeyInit};
use sha2::{Digest, Sha256};
use socksaddr::SocksAddr;
use uuid::Uuid;
use worker::{Error, Result};

use crate::{
    config::VmessInbound,
    proxy::inbound::codec::{Codec, Decoder, Encoder},
};

use super::{Attempt, InitialRequest};

pub(in crate::proxy) mod codec;
mod utils;

thread_local! {
    static SEEN_AUTH_IDS: RefCell<HashMap<[u8; 16], i64>> = RefCell::new(HashMap::new());
}

pub(super) async fn parse(chunk: &[u8], config: &VmessInbound) -> Result<Attempt> {
    let Some((auth, cmd_key, time)) = config.users.iter().find_map(|user| {
        Uuid::parse_str(&user.uuid)
            .ok()
            .filter(|uuid| uuid.get_version() == Some(uuid::Version::Random))
            .and_then(|uuid| {
                let auth: [u8; 16] = chunk
                    .get(..16)
                    .and_then(|bytes| <[u8; 16]>::try_from(bytes).ok())?;
                let mut seed = uuid.as_bytes().to_vec();
                seed.extend_from_slice(b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
                let cmd_key = md5::compute(seed).0;
                let mut block = auth.into();
                Aes128::new_from_slice(&utils::kdf16(&cmd_key, &[b"AES Auth ID Encryption"]))
                    .ok()?
                    .decrypt_block(&mut block);
                let time = i64::from_be_bytes(
                    block
                        .get(..8)
                        .and_then(|bytes| <[u8; 8]>::try_from(bytes).ok())?,
                );
                let crc = u32::from_be_bytes(
                    block
                        .get(12..16)
                        .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())?,
                );
                let authenticated = block.get(..12)?;
                (crc == crc32fast::hash(authenticated)
                    && (i128::from(utils::now()) - i128::from(time)).abs()
                        <= i128::from(utils::CLOCK_SKEW))
                .then_some((auth, cmd_key, time))
            })
    }) else {
        return Ok(Attempt::NotRecognized);
    };
    if chunk.len() < 42 {
        return Ok(Attempt::Incomplete);
    }
    let connection_nonce = chunk
        .get(34..42)
        .ok_or_else(|| utils::invalid_at("invalid encrypted request"))?;
    let size = u16::from_be_bytes(
        utils::open(
            utils::kdf16(
                &cmd_key,
                &[b"VMess Header AEAD Key_Length", &auth, connection_nonce],
            ),
            utils::nonce(
                &cmd_key,
                &[b"VMess Header AEAD Nonce_Length", &auth, connection_nonce],
            ),
            chunk
                .get(16..34)
                .ok_or_else(|| utils::invalid_at("invalid encrypted request"))?,
            &auth,
            "header length authentication failed",
        )
        .await?
        .as_slice()
        .try_into()
        .map_err(|_| utils::invalid_at("invalid encrypted request"))?,
    ) as usize;
    if !(41..=utils::MAX_HEADER).contains(&size) {
        return Err(utils::invalid_at("invalid header length"));
    }
    let total = 42 + size + 16;
    if chunk.len() < total {
        return Ok(Attempt::Incomplete);
    }
    let header = utils::open(
        utils::kdf16(
            &cmd_key,
            &[b"VMess Header AEAD Key", &auth, connection_nonce],
        ),
        utils::nonce(
            &cmd_key,
            &[b"VMess Header AEAD Nonce", &auth, connection_nonce],
        ),
        chunk
            .get(42..total)
            .ok_or_else(|| utils::invalid_at("invalid encrypted request"))?,
        &auth,
        "header authentication failed",
    )
    .await?;
    if header.len() != size || header.first() != Some(&1) {
        return Err(utils::invalid_at("invalid header version or size"));
    }
    let mut iv = [0_u8; 16];
    let mut key = [0_u8; 16];
    iv.copy_from_slice(
        header
            .get(1..17)
            .ok_or_else(|| utils::invalid_at("invalid encrypted request"))?,
    );
    key.copy_from_slice(
        header
            .get(17..33)
            .ok_or_else(|| utils::invalid_at("invalid encrypted request"))?,
    );
    let option = header
        .get(34)
        .copied()
        .ok_or_else(|| utils::invalid_at("invalid encrypted request"))?;
    let security_padding = header
        .get(35)
        .copied()
        .ok_or_else(|| utils::invalid_at("invalid encrypted request"))?;
    let security = security_padding & 0x0f;
    let command = header
        .get(37)
        .copied()
        .ok_or_else(|| utils::invalid_at("invalid encrypted request"))?;
    let mux_cool = command == 3;
    if !matches!(security, 3 | 4)
        || header.get(36) != Some(&0)
        || !(command == 1 || mux_cool)
        || option & !0x0d != 0
        || option & 0x01 == 0
        || (option & 0x08 != 0 && option & 0x04 == 0)
    {
        tracing::error!("vmess: unsupported command, security, or options");
        return Err(Error::RustError("unsupported encrypted stream mode".into()));
    }
    let (hostname, port, index) = if mux_cool {
        ("v1.mux.cool".to_string(), 9527, 38)
    } else {
        let address = header
            .get(38..)
            .ok_or_else(|| utils::invalid_at("invalid request address"))?;
        let (addr, consumed) = SocksAddr::parse_xray(address)
            .map_err(|_| utils::invalid_at("invalid request address"))?;
        (addr.host().into_owned(), addr.port(), 38 + consumed)
    };
    if index + usize::from(security_padding >> 4) + 4 != size {
        return Err(utils::invalid_at("invalid header padding"));
    }
    let checksum_start = size - 4;
    let checksum_input = header
        .get(..checksum_start)
        .ok_or_else(|| utils::invalid_at("invalid encrypted request"))?;
    let checksum = header
        .get(checksum_start..)
        .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
        .ok_or_else(|| utils::invalid_at("invalid encrypted request"))?;
    if checksum_input.iter().fold(0x811c_9dc5_u32, |hash, byte| {
        (hash ^ u32::from(*byte)).wrapping_mul(0x0100_0193)
    }) != u32::from_be_bytes(checksum)
    {
        return Err(utils::invalid_at("header checksum mismatch"));
    }
    SEEN_AUTH_IDS.with(|seen| {
        let mut seen = seen.borrow_mut();
        let current = utils::now();
        if seen
            .get(&auth)
            .is_some_and(|expires_at| *expires_at >= current)
        {
            return Err(utils::invalid_at("replayed authentication ID"));
        }
        if seen.len() >= 32 * 1024 {
            seen.retain(|_, expires_at| *expires_at >= current);
            if seen.len() >= 32 * 1024 {
                return Err(utils::invalid_at("authentication replay cache full"));
            }
        }
        seen.insert(auth, time.saturating_add(utils::CLOCK_SKEW));
        Ok(())
    })?;
    tracing::info!("vmess: request header authenticated");
    let response_key: [u8; 16] = Sha256::digest(key)
        .get(..16)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| utils::invalid_at("invalid encrypted request"))?;
    let response_iv: [u8; 16] = Sha256::digest(iv)
        .get(..16)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| utils::invalid_at("invalid encrypted request"))?;
    let mut response = utils::seal(
        utils::kdf16(&response_key, &[b"AEAD Resp Header Len Key"]),
        utils::nonce(&response_iv, &[b"AEAD Resp Header Len IV"]),
        &4_u16.to_be_bytes(),
    )
    .await?;
    response.extend(
        utils::seal(
            utils::kdf16(&response_key, &[b"AEAD Resp Header Key"]),
            utils::nonce(&response_iv, &[b"AEAD Resp Header IV"]),
            &[
                header
                    .get(33)
                    .copied()
                    .ok_or_else(|| utils::invalid_at("invalid encrypted request"))?,
                0,
                0,
                0,
            ],
        )
        .await?,
    );
    let mut inbound = Decoder::Vmess(Box::new(codec::ChunkDecoder {
        cipher: codec::body_cipher(key, security).await?,
        iv,
        options: option,
        masker: utils::masker(&iv, option),
        counter: 0,
        pending: Vec::new(),
        expected: None,
        ended: false,
    }));
    let payload = inbound
        .decode(
            chunk
                .get(total..)
                .ok_or_else(|| utils::invalid_at("invalid encrypted request"))?,
        )
        .await?
        .into_owned();
    tracing::info!("protocol: vmess selected");
    Ok(Attempt::Parsed(Box::new(InitialRequest {
        hostname,
        port,
        is_udp: false,
        payload,
        codec: Codec {
            inbound,
            outbound: Encoder::Vmess(Box::new(codec::ChunkEncoder {
                cipher: codec::body_cipher(response_key, security).await?,
                iv: response_iv,
                options: option,
                masker: utils::masker(&response_iv, option),
                counter: 0,
                header: Some(response),
            })),
        },
    })))
}
