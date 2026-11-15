#[allow(clippy::single_call_fn)]
pub(super) mod codec;
#[allow(clippy::single_call_fn)]
mod shadowsocks;
#[allow(clippy::single_call_fn)]
mod trojan;
#[allow(clippy::single_call_fn)]
mod vless;
#[allow(clippy::single_call_fn)]
mod vmess;

pub(crate) use super::transport::handle;

use worker::{Error, Result};

use crate::config::InboundConfig;

pub(super) struct InitialRequest {
    pub(super) hostname: String,
    pub(super) port: u16,
    pub(super) is_udp: bool,
    pub(super) payload: Vec<u8>,
    pub(super) codec: codec::Codec,
}

enum Attempt {
    NotRecognized,
    Incomplete,
    Parsed(Box<InitialRequest>),
}

impl InitialRequest {
    #[allow(clippy::single_call_fn)]
    pub(super) async fn parse(chunk: &[u8], inbounds: &[InboundConfig]) -> Result<Option<Self>> {
        if chunk.len() < 16 {
            return Ok(None);
        }

        macro_rules! probe {
            ($attempt:expr) => {
                match $attempt {
                    NotRecognized => {}
                    Incomplete => return Ok(None),
                    Parsed(request) => return Ok(Some(*request)),
                }
            };
        }
        for inbound in inbounds {
            if let InboundConfig::Shadowsocks(config) = inbound {
                probe!(shadowsocks::parse(chunk, config).await?);
            }
        }
        for inbound in inbounds {
            if let InboundConfig::Vmess(config) = inbound {
                probe!(vmess::parse(chunk, config).await?);
            }
        }
        for inbound in inbounds {
            if let InboundConfig::Vless(config) = inbound {
                probe!(vless::parse(chunk, config)?);
            }
        }
        let trojan_configs = inbounds.iter().filter_map(|inbound| match inbound {
            InboundConfig::Trojan(config) => Some(config),
            _ => None,
        });
        probe!(trojan::parse(chunk, trojan_configs)?);

        if chunk.len() < 32 + 2 + 16 {
            return Ok(None);
        }
        tracing::info!("protocol: no matching request format");
        Err(Error::RustError("invalid request".into()))
    }
}

use Attempt::{Incomplete, NotRecognized, Parsed};
