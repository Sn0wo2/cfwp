use std::io;

use mux_core::{Event, Muxer, invalid};
use socksaddr::SocksAddr;

const KEEP: u8 = 2;
const END: u8 = 3;
const OPTION_DATA: u8 = 1;
const OPTION_ERROR: u8 = 2;
const MAX_META: usize = 512;

#[derive(Clone, Copy, Debug, Default)]
#[allow(clippy::exhaustive_structs)]
pub struct Decoder;

impl Muxer for Decoder {
    fn decode(&self, buf: &mut Vec<u8>) -> io::Result<Vec<Event>> {
        let Some(frame_len) = buf
            .get(..2)
            .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
        else {
            return Ok(Vec::new());
        };
        let meta_len = usize::from(u16::from_be_bytes(frame_len));
        if meta_len > MAX_META {
            return Err(invalid("invalid mux.cool metadata length"));
        }
        let Some(meta) = buf.get(2..2 + meta_len) else {
            return Ok(Vec::new());
        };
        let Some(meta_header) = meta
            .get(..4)
            .and_then(|header| <[u8; 4]>::try_from(header).ok())
        else {
            return Err(invalid("invalid mux.cool metadata"));
        };
        let [sid_0, sid_1, status, option] = meta_header;
        let sid = u32::from(u16::from_be_bytes([sid_0, sid_1]));
        let (event, data_len) = match status {
            1 => {
                let Some((&network, address_bytes)) =
                    meta.get(4..).and_then(|tail| tail.split_first())
                else {
                    return Err(invalid("invalid mux.cool new frame"));
                };
                let (addr, _) = SocksAddr::parse_xray(address_bytes).map_err(|err| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid mux.cool target: {err}"),
                    )
                })?;
                let event = match network {
                    1 if sid == 0 => Event::Reject { sid },
                    1 => Event::Open {
                        sid,
                        target: Some(addr),
                    },
                    2 => Event::Reject { sid },
                    _ => return Err(invalid("invalid mux.cool network")),
                };
                (Some(event), None)
            }
            KEEP => {
                if meta.get(4).copied() == Some(2) {
                    (Some(Event::Reject { sid }), None)
                } else if option & OPTION_DATA != 0 {
                    let Some(data_len_bytes) = buf
                        .get(2 + meta_len..4 + meta_len)
                        .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
                    else {
                        return Ok(Vec::new());
                    };
                    let data_len = usize::from(u16::from_be_bytes(data_len_bytes));
                    let Some(data) = buf
                        .get(4 + meta_len..4 + meta_len + data_len)
                        .map(<[u8]>::to_vec)
                    else {
                        return Ok(Vec::new());
                    };
                    let event = (data_len > 0).then_some(Event::Data { sid, data });
                    (event, Some(data_len))
                } else {
                    (None, None)
                }
            }
            END => (
                Some(if option & OPTION_ERROR != 0 {
                    Event::Reset { sid }
                } else {
                    Event::Eof { sid }
                }),
                None,
            ),
            4 => (None, None),
            _ => return Err(invalid("invalid mux.cool status")),
        };
        buf.drain(..4 + meta_len + data_len.map_or(0, |len| 2 + len));
        Ok(event.into_iter().collect())
    }

    fn chunk_limit(&self) -> usize {
        u16::MAX as usize
    }

    fn data_frame(&self, sid: u32, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + data.len());
        out.extend_from_slice(&4_u16.to_be_bytes());
        let [_, _, sid_0, sid_1] = sid.to_be_bytes();
        out.extend_from_slice(&[sid_0, sid_1]);
        out.push(KEEP);
        out.push(OPTION_DATA);
        out.extend_from_slice(&(data.len() as u16).to_be_bytes());
        out.extend_from_slice(data);
        out
    }

    fn eof_frame(&self, sid: u32) -> Vec<u8> {
        end_frame(sid, false)
    }

    fn reset_frame(&self, sid: u32) -> Vec<u8> {
        end_frame(sid, true)
    }
}

fn end_frame(sid: u32, error: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(6);
    out.extend_from_slice(&4_u16.to_be_bytes());
    let [_, _, sid_0, sid_1] = sid.to_be_bytes();
    out.extend_from_slice(&[sid_0, sid_1]);
    out.push(END);
    out.push(if error { OPTION_ERROR } else { 0 });
    out
}
