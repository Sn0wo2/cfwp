use sha2::{Digest, Sha224};
use socksaddr::{ParseError, SocksAddr};
use worker::{Error, Result};

use crate::config::TrojanInbound;

use super::{Attempt, InitialRequest, codec::Codec};

pub(super) fn parse<'a>(
    chunk: &[u8],
    mut inbounds: impl Iterator<Item = &'a TrojanInbound>,
) -> Result<Attempt> {
    if !chunk
        .get(..16)
        .is_some_and(|auth| auth.iter().all(u8::is_ascii_hexdigit))
    {
        return Ok(Attempt::NotRecognized);
    }
    tracing::info!("protocol: trojan selected");
    tracing::info!("trojan: received header candidate ({} bytes)", chunk.len());
    if chunk.len() < 60 {
        tracing::info!("trojan: waiting for header");
        return Ok(Attempt::Incomplete);
    }
    if chunk.get(56..58) != Some(b"\r\n") {
        tracing::error!("trojan: invalid authentication delimiter");
        return Err(Error::RustError("invalid request header".into()));
    }
    let provided = std::str::from_utf8(
        chunk
            .get(..56)
            .ok_or_else(|| Error::RustError("invalid access token".into()))?,
    )
    .map_err(|_| Error::RustError("invalid access token".into()))?;
    let authenticated = inbounds.any(|config| {
        config
            .users
            .iter()
            .any(|user| provided == hex::encode(Sha224::digest(user.password.as_bytes())))
    });
    if !authenticated {
        tracing::error!("trojan: authentication failed");
        return Err(Error::RustError("invalid access token".into()));
    }
    tracing::info!("trojan: authenticated");

    let socks = chunk
        .get(58..)
        .ok_or_else(|| Error::RustError("invalid request header".into()))?;
    let command = socks
        .first()
        .copied()
        .ok_or_else(|| Error::RustError("invalid request header".into()))?;
    if command != 1 {
        tracing::error!("trojan: unsupported command {command}");
        return Err(Error::RustError("unsupported stream mode".into()));
    }
    let socks = socks
        .get(1..)
        .ok_or_else(|| Error::RustError("invalid request header".into()))?;
    let (addr, address_end) = match SocksAddr::parse_socks(socks) {
        Ok(parsed) => parsed,
        Err(ParseError::Truncated) => {
            tracing::info!("trojan: waiting for route header");
            return Ok(Attempt::Incomplete);
        }
        Err(ParseError::Invalid(message)) => return Err(Error::RustError(message.into())),
    };
    let delimiter_end = address_end
        .checked_add(2)
        .ok_or_else(|| Error::RustError("invalid request header".into()))?;
    if socks.len() < delimiter_end {
        tracing::info!("trojan: waiting for route header");
        return Ok(Attempt::Incomplete);
    }
    if socks.get(address_end..delimiter_end) != Some(b"\r\n") {
        tracing::error!("trojan: invalid route delimiter");
        return Err(Error::RustError("invalid frame delimiter".into()));
    }
    let payload = socks
        .get(delimiter_end..)
        .ok_or_else(|| Error::RustError("invalid request header".into()))?
        .to_vec();
    tracing::info!(
        "trojan: request parsed (addr={addr}, payload={} bytes)",
        payload.len()
    );
    Ok(Attempt::Parsed(Box::new(InitialRequest {
        hostname: addr.host().into_owned(),
        port: addr.port(),
        is_udp: false,
        payload,
        codec: Codec::plain(None),
    })))
}
