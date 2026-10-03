use std::cell::{Cell, RefCell};
use std::future::poll_fn;
use std::io;
use std::rc::Rc;
use std::task::{Poll, Waker};

use mux_core::{Event, Muxer, invalid};

pub const MAX_FRAME: usize = 32 * 1024;

const FIN: u8 = 1;
const PSH: u8 = 2;
const HEADER: usize = 8;
const UPD_PAYLOAD: usize = 8;

#[derive(Clone, Debug)]
pub struct Bucket(Rc<Inner>);

#[derive(Debug)]
struct Inner {
    value: Cell<i64>,
    waker: RefCell<Option<Waker>>,
}

impl Bucket {
    pub fn new() -> Self {
        Self(Rc::new(Inner {
            value: Cell::new(4 * 1024 * 1024),
            waker: RefCell::new(None),
        }))
    }

    pub fn add(&self, n: usize) {
        self.0.value.set(self.0.value.get() + n as i64);
        if let Some(waker) = self.0.waker.borrow_mut().take() {
            waker.wake();
        }
    }

    pub async fn wait_available(&self) {
        poll_fn(|cx| {
            if self.0.value.get() > 0 {
                return Poll::Ready(());
            }
            *self.0.waker.borrow_mut() = Some(cx.waker().clone());
            Poll::Pending
        })
        .await;
    }
}

impl Default for Bucket {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct Decoder {
    bucket: Bucket,
}

impl Decoder {
    pub const fn new(bucket: Bucket) -> Self {
        Self { bucket }
    }
}

impl Muxer for Decoder {
    fn decode(&self, buf: &mut Vec<u8>) -> io::Result<Vec<Event>> {
        let Some(header) = buf
            .get(..HEADER)
            .and_then(|header| <[u8; HEADER]>::try_from(header).ok())
        else {
            return Ok(Vec::new());
        };
        let [version, command, len_0, len_1, sid_0, sid_1, sid_2, sid_3] = header;
        if version != 1 {
            return Err(invalid("invalid smux version"));
        }
        let len = usize::from(u16::from_le_bytes([len_0, len_1]));
        let sid = u32::from_le_bytes([sid_0, sid_1, sid_2, sid_3]);
        match command {
            0 => {
                buf.drain(..HEADER);
                Ok(vec![Event::Open { sid, target: None }])
            }
            FIN => {
                buf.drain(..HEADER);
                Ok(vec![Event::Eof { sid }])
            }
            3 => {
                buf.drain(..HEADER);
                Ok(Vec::new())
            }
            4 => {
                if buf.get(..HEADER + UPD_PAYLOAD).is_none() {
                    return Ok(Vec::new());
                }
                buf.drain(..HEADER + UPD_PAYLOAD);
                Ok(Vec::new())
            }
            PSH => {
                let Some(data) = buf.get(HEADER..HEADER + len).map(<[u8]>::to_vec) else {
                    return Ok(Vec::new());
                };
                let bucket = &self.bucket.0;
                bucket.value.set(bucket.value.get() - len as i64);
                buf.drain(..HEADER + len);
                if data.is_empty() {
                    return Ok(Vec::new());
                }
                Ok(vec![Event::Data { sid, data }])
            }
            _ => Err(invalid("invalid smux command")),
        }
    }

    fn chunk_limit(&self) -> usize {
        MAX_FRAME
    }

    fn data_frame(&self, sid: u32, data: &[u8]) -> Vec<u8> {
        frame(PSH, sid, data)
    }

    fn eof_frame(&self, sid: u32) -> Vec<u8> {
        frame(FIN, sid, &[])
    }

    fn reset_frame(&self, sid: u32) -> Vec<u8> {
        frame(FIN, sid, &[])
    }
}

fn frame(cmd: u8, sid: u32, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER + data.len());
    out.push(1);
    out.push(cmd);
    out.extend_from_slice(&(data.len() as u16).to_le_bytes());
    out.extend_from_slice(&sid.to_le_bytes());
    out.extend_from_slice(data);
    out
}
