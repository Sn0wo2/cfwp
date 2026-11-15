use std::borrow::Cow;

use worker::Result;

use super::{shadowsocks, vmess};

pub(in crate::proxy) enum Decoder {
    Plain,
    Shadowsocks(Box<shadowsocks::codec::ChunkDecoder>),
    Vmess(Box<vmess::codec::ChunkDecoder>),
}

pub(in crate::proxy) enum Encoder {
    Plain { response_header: Option<Vec<u8>> },
    Shadowsocks(Box<shadowsocks::codec::ChunkEncoder>),
    Vmess(Box<vmess::codec::ChunkEncoder>),
}

pub(in crate::proxy) struct Codec {
    pub(in crate::proxy) inbound: Decoder,
    pub(in crate::proxy) outbound: Encoder,
}

impl Codec {
    pub(in crate::proxy) const fn plain(response_header: Option<Vec<u8>>) -> Self {
        Self {
            inbound: Decoder::Plain,
            outbound: Encoder::Plain { response_header },
        }
    }
}

impl Decoder {
    pub(in crate::proxy) async fn decode<'a>(&mut self, bytes: &'a [u8]) -> Result<Cow<'a, [u8]>> {
        match self {
            Self::Plain => Ok(Cow::Borrowed(bytes)),
            Self::Shadowsocks(decoder) => decoder.decode(bytes).await,
            Self::Vmess(decoder) => decoder.decode(bytes).await,
        }
    }
}

impl Encoder {
    pub(in crate::proxy) async fn encode<'a>(&mut self, bytes: &'a [u8]) -> Result<Cow<'a, [u8]>> {
        match self {
            Self::Plain { response_header } => response_header.take().map_or_else(
                || Ok(Cow::Borrowed(bytes)),
                |header| {
                    let mut result = header;
                    result.extend_from_slice(bytes);
                    Ok(Cow::Owned(result))
                },
            ),
            Self::Shadowsocks(encoder) => encoder.encode(bytes).await,
            Self::Vmess(encoder) => encoder.encode(bytes).await,
        }
    }
}
