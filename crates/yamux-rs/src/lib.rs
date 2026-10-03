use std::cell::RefCell;
use std::collections::HashMap;
use std::future::poll_fn;
use std::io;
use std::task::{Poll, Waker};

use mux_core::{Event, Muxer, invalid};

pub const WINDOW: u32 = 256 * 1024;
pub const MAX_FRAME: usize = 64 * 1024;

const WU: u8 = 1;
const PING: u8 = 2;
const FLAG_SYN: u16 = 1;
const FLAG_ACK: u16 = 2;
const FLAG_FIN: u16 = 4;
const FLAG_RST: u16 = 8;
const HEADER: usize = 12;

#[derive(Clone, Copy, Debug, Default)]
#[allow(clippy::exhaustive_structs)]
pub struct Decoder;

impl Muxer for Decoder {
    fn decode(&self, buf: &mut Vec<u8>) -> io::Result<Vec<Event>> {
        let Some(header) = buf
            .get(..HEADER)
            .and_then(|header| <[u8; HEADER]>::try_from(header).ok())
        else {
            return Ok(Vec::new());
        };
        let [
            version,
            typ,
            flag_0,
            flag_1,
            sid_0,
            sid_1,
            sid_2,
            sid_3,
            len_0,
            len_1,
            len_2,
            len_3,
        ] = header;
        if version != 0 {
            return Err(invalid("invalid yamux version"));
        }
        let flags = u16::from_be_bytes([flag_0, flag_1]);
        let sid = u32::from_be_bytes([sid_0, sid_1, sid_2, sid_3]);
        let length = usize::try_from(u32::from_be_bytes([len_0, len_1, len_2, len_3]))
            .map_err(|_| invalid("yamux frame too large"))?;
        let mut events = Vec::new();
        if flags & FLAG_SYN != 0 {
            events.push(Event::Open { sid, target: None });
        }
        if flags & FLAG_FIN != 0 {
            events.push(Event::Eof { sid });
        }
        if flags & FLAG_RST != 0 {
            events.push(Event::Reset { sid });
        }
        match typ {
            0 => {
                if length > WINDOW as usize {
                    return Err(invalid("yamux receive window exceeded"));
                }
                let Some(data) = buf.get(HEADER..HEADER + length) else {
                    return Ok(Vec::new());
                };
                if length > 0 {
                    events.push(Event::Data {
                        sid,
                        data: data.to_vec(),
                    });
                }
                buf.drain(..HEADER + length);
            }
            WU => {
                buf.drain(..HEADER);
                if events.is_empty() && length > 0 {
                    events.push(Event::Window {
                        sid,
                        delta: length as u32,
                    });
                }
            }
            PING => {
                buf.drain(..HEADER);
                if flags & FLAG_SYN != 0 {
                    events.push(Event::Ping {
                        value: length as u32,
                    });
                }
            }
            3 => {
                buf.drain(..HEADER);
                events.push(Event::Closed);
            }
            _ => return Err(invalid("invalid yamux type")),
        }
        Ok(events)
    }

    fn chunk_limit(&self) -> usize {
        MAX_FRAME
    }

    fn data_frame(&self, sid: u32, data: &[u8]) -> Vec<u8> {
        frame(0, 0, sid, data.len() as u32, data)
    }

    fn eof_frame(&self, sid: u32) -> Vec<u8> {
        frame(0, FLAG_FIN, sid, 0, &[])
    }

    fn reset_frame(&self, sid: u32) -> Vec<u8> {
        frame(WU, FLAG_RST, sid, 0, &[])
    }

    fn ping_ack(&self, value: u32) -> Option<Vec<u8>> {
        Some(frame(PING, FLAG_ACK, 0, value, &[]))
    }
}

fn frame(typ: u8, flags: u16, sid: u32, length: u32, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER + data.len());
    out.push(0);
    out.push(typ);
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&sid.to_be_bytes());
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(data);
    out
}

#[derive(Debug, Default)]
pub struct Windows {
    send: RefCell<HashMap<u32, u32>>,
    pending: RefCell<HashMap<u32, u32>>,
    waker: RefCell<Option<Waker>>,
}

impl Windows {
    pub fn open(&self, sid: u32) -> Vec<u8> {
        self.send.borrow_mut().insert(sid, WINDOW);
        self.pending.borrow_mut().insert(sid, 0);
        frame(WU, FLAG_ACK, sid, 0, &[])
    }

    pub fn close(&self, sid: u32) {
        self.send.borrow_mut().remove(&sid);
        self.pending.borrow_mut().remove(&sid);
        if let Some(waker) = self.waker.borrow_mut().take() {
            waker.wake();
        }
    }

    pub fn clear(&self) {
        self.send.borrow_mut().clear();
        self.pending.borrow_mut().clear();
        if let Some(waker) = self.waker.borrow_mut().take() {
            waker.wake();
        }
    }

    pub fn recv_forwarded(&self, sid: u32, n: usize) -> Option<Vec<u8>> {
        let mut pending = self.pending.borrow_mut();
        let owed = pending.get_mut(&sid)?;
        *owed += n as u32;
        if *owed < WINDOW / 2 {
            return None;
        }
        let delta = *owed;
        *owed = 0;
        Some(frame(WU, FLAG_ACK, sid, delta, &[]))
    }

    pub fn grant(&self, sid: u32, delta: u32) {
        if let Some(window) = self.send.borrow_mut().get_mut(&sid) {
            *window = window.saturating_add(delta);
        }
        if let Some(waker) = self.waker.borrow_mut().take() {
            waker.wake();
        }
    }

    pub async fn acquire(&self, sid: u32, want: usize) -> usize {
        poll_fn(|cx| {
            let mut send = self.send.borrow_mut();
            let Some(window) = send.get_mut(&sid) else {
                return Poll::Ready(0);
            };
            if *window == 0 {
                *self.waker.borrow_mut() = Some(cx.waker().clone());
                return Poll::Pending;
            }
            let granted = (*window as usize).min(want);
            *window -= granted as u32;
            Poll::Ready(granted)
        })
        .await
    }
}
