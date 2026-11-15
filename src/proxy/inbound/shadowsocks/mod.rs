use std::cell::RefCell;

use hashlink::LinkedHashSet;
use shadowsocks_crypto::{CipherKind, v1::openssl_bytes_to_key};
use socksaddr::{ParseError, SocksAddr};
use worker::{Error, Result};

use crate::{
    config::ShadowsocksInbound,
    proxy::inbound::codec::{Codec, Decoder, Encoder},
};

use super::{Attempt, InitialRequest};

pub(in crate::proxy) mod codec;

thread_local! {
    static SEEN_SALTS: RefCell<LinkedHashSet<(usize, Vec<u8>)>> =
        RefCell::new(LinkedHashSet::new());
}

pub(super) async fn parse(chunk: &[u8], config: &ShadowsocksInbound) -> Result<Attempt> {
    let (kind, kind_index) = match config.method.as_str() {
        "aes-128-gcm" => (CipherKind::AES_128_GCM, 0),
        "aes-256-gcm" => (CipherKind::AES_256_GCM, 1),
        "chacha20-ietf-poly1305" => (CipherKind::CHACHA20_POLY1305, 2),
        _ => return Ok(Attempt::NotRecognized),
    };
    let salt_len = kind.salt_len();
    let header_len = salt_len + 2 + kind.tag_len();
    if chunk.len() < header_len {
        return Ok(Attempt::NotRecognized);
    }
    let salt_bytes = chunk
        .get(..salt_len)
        .ok_or_else(|| Error::RustError("invalid request".into()))?;
    let mut key = vec![0; kind.key_len()];
    openssl_bytes_to_key(config.password.as_bytes(), &mut key);
    let mut decoder = codec::ChunkDecoder {
        cipher: codec::Cipher::new(kind, &key, salt_bytes).await?,
        pending: Vec::new(),
        expected: None,
    };
    let encrypted_address = chunk
        .get(salt_len..header_len)
        .ok_or_else(|| Error::RustError("invalid request".into()))?;
    if decoder.decode(encrypted_address).await.is_err() {
        return Ok(Attempt::NotRecognized);
    }
    let encrypted_payload = chunk
        .get(header_len..)
        .ok_or_else(|| Error::RustError("invalid request".into()))?;
    let decrypted = decoder.decode(encrypted_payload).await?;
    let (addr, address_index) = match SocksAddr::parse_socks(&decrypted) {
        Ok(parsed) => parsed,
        Err(ParseError::Truncated) => return Ok(Attempt::Incomplete),
        Err(ParseError::Invalid(message)) => return Err(Error::RustError(message.into())),
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
        if seen.len() > 32 * 1024 {
            seen.pop_front();
        }
        Ok(())
    })?;
    tracing::info!("protocol: shadowsocks selected");
    let mut salt = vec![0; kind.salt_len()];
    getrandom::fill(&mut salt)
        .map_err(|err| Error::RustError(format!("Shadowsocks salt generation failed: {err}")))?;
    Ok(Attempt::Parsed(Box::new(InitialRequest {
        hostname: addr.host().into_owned(),
        port: addr.port(),
        is_udp: false,
        payload: decrypted
            .get(address_index..)
            .ok_or_else(|| Error::RustError("invalid request".into()))?
            .to_vec(),
        codec: Codec {
            inbound: Decoder::Shadowsocks(Box::new(decoder)),
            outbound: Encoder::Shadowsocks(Box::new(codec::ChunkEncoder {
                cipher: codec::Cipher::new(kind, &key, &salt).await?,
                salt: Some(salt),
            })),
        },
    })))
}
