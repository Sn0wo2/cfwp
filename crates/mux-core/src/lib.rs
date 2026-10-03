use std::io;

use socksaddr::SocksAddr;

pub fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[derive(Debug)]
#[allow(clippy::exhaustive_enums)]
pub enum Event {
    Open { sid: u32, target: Option<SocksAddr> },
    Data { sid: u32, data: Vec<u8> },
    Eof { sid: u32 },
    Reset { sid: u32 },
    Reject { sid: u32 },
    Window { sid: u32, delta: u32 },
    Ping { value: u32 },
    Closed,
}

pub trait Muxer {
    fn decode(&self, buf: &mut Vec<u8>) -> io::Result<Vec<Event>>;
    fn chunk_limit(&self) -> usize;
    fn data_frame(&self, sid: u32, data: &[u8]) -> Vec<u8>;
    fn eof_frame(&self, sid: u32) -> Vec<u8>;
    fn reset_frame(&self, sid: u32) -> Vec<u8>;
    fn ping_ack(&self, _value: u32) -> Option<Vec<u8>> {
        None
    }
}
