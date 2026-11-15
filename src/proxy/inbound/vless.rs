use socksaddr::{ParseError, SocksAddr};
use uuid::Uuid;
use worker::{Error, Result};

use crate::config::VlessInbound;

use super::{Attempt, InitialRequest, codec::Codec};

pub(super) fn parse(chunk: &[u8], config: &VlessInbound) -> Result<Attempt> {
    if !chunk.get(..17).is_some_and(|header| {
        header.first() == Some(&0)
            && config.users.iter().any(|user| {
                Uuid::parse_str(&user.uuid)
                    .ok()
                    .filter(|uuid| uuid.get_version() == Some(uuid::Version::Random))
                    .is_some_and(|id| header.get(1..17) == Some(id.as_bytes().as_slice()))
            })
    }) {
        return Ok(Attempt::NotRecognized);
    }
    tracing::info!("protocol: vless selected");
    if chunk.len() < 19 {
        return Ok(Attempt::Incomplete);
    }
    if chunk.get(17) != Some(&0) {
        return Err(Error::RustError("unsupported VLESS addons".into()));
    }
    if chunk.len() < 22 {
        return Ok(Attempt::Incomplete);
    }
    let command = chunk
        .get(18)
        .copied()
        .ok_or_else(|| Error::RustError("invalid VLESS header".into()))?;
    if !matches!(command, 1..=3) {
        return Err(Error::RustError("unsupported route mode".into()));
    }
    if command == 3 {
        tracing::info!(
            "protocol: vless mux.cool session (payload={}B)",
            chunk.len() - 19
        );
        return Ok(Attempt::Parsed(Box::new(InitialRequest {
            hostname: "v1.mux.cool".to_string(),
            port: 9527,
            is_udp: false,
            payload: chunk
                .get(19..)
                .ok_or_else(|| Error::RustError("invalid VLESS header".into()))?
                .to_vec(),
            codec: Codec::plain(Some(vec![0, 0])),
        })));
    }
    let (addr, addr_len) = match SocksAddr::parse_xray(
        chunk
            .get(19..)
            .ok_or_else(|| Error::RustError("invalid VLESS header".into()))?,
    ) {
        Ok(parsed) => parsed,
        Err(ParseError::Truncated) => return Ok(Attempt::Incomplete),
        Err(ParseError::Invalid(message)) => return Err(Error::RustError(message.into())),
    };
    let payload = chunk
        .get(19 + addr_len..)
        .ok_or_else(|| Error::RustError("invalid VLESS header".into()))?
        .to_vec();
    tracing::info!(
        "identity-header parsed: rev=0 opt=0 mode={} route={addr} datagram={} payload={}B",
        command,
        command == 2,
        payload.len()
    );
    Ok(Attempt::Parsed(Box::new(InitialRequest {
        hostname: addr.host().into_owned(),
        port: addr.port(),
        is_udp: command == 2,
        payload,
        codec: Codec::plain(Some(vec![0, 0])),
    })))
}
