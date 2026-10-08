use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::future::{Future, poll_fn};
use std::pin::{Pin, pin};
use std::rc::Rc;
use std::task::{Poll, Waker};

use futures_channel::mpsc::UnboundedSender;
use futures_util::StreamExt;
use futures_util::future::{Either, select};
use mux_core::{Event, Muxer};
use socksaddr::{ParseError, SocksAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Semaphore;
use worker::{Error, Result, WebSocket, WebsocketEvent};

use super::protocol::{Codec, Decoder};
use super::util::{CONNECT_TIMEOUT_MS, connect_tcp};
use crate::util::with_timeout;

pub(super) const SING_MUX_HOST: &str = "sp.mux.sing-box.arpa";
pub(super) const SING_MUX_PORT: u16 = 444;
pub(super) const MUX_COOL_HOST: &str = "v1.mux.cool";
pub(super) const MUX_COOL_PORT: u16 = 9527;

const OUTBOX_CAPACITY: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum MuxMode {
    SingMux,
    MuxCool,
}

#[derive(Default)]
struct StreamShared {
    buffer: VecDeque<Vec<u8>>,
    buffered_len: usize,
    eof: bool,
    waker: Option<Waker>,
}

impl StreamShared {
    fn close_read(&mut self) {
        self.eof = true;
        if let Some(waker) = self.waker.take() {
            waker.wake();
        }
    }
}

type Shared = Rc<RefCell<StreamShared>>;

type Task = Rc<RefCell<Pin<Box<dyn Future<Output = LoopEvent>>>>>;

enum StreamPhase {
    Preparing,
    Active { fut: Task },
}

struct Stream {
    shared: Shared,
    phase: StreamPhase,
}

struct Job {
    bytes: Vec<u8>,
    budget: usize,
}

struct Outbox {
    tx: UnboundedSender<Job>,
    budget: Semaphore,
}

impl Outbox {
    fn send(&self, bytes: Vec<u8>) {
        drop(self.tx.unbounded_send(Job { bytes, budget: 0 }));
    }

    async fn send_framed(&self, bytes: Vec<u8>) {
        let budget = bytes.len().min(OUTBOX_CAPACITY);
        if budget > 0 {
            let Ok(permit) = self.budget.acquire_many(budget as u32).await else {
                return;
            };
            permit.forget();
        }
        drop(self.tx.unbounded_send(Job { bytes, budget }));
    }
}

enum LoopEvent {
    Raw(Event),
    ReaderDone,
    WriterDone,
    Connected(u32, worker::Socket),
    ConnectFailed(u32, Error),
    PumpDone(u32, std::io::Result<(u64, u64)>),
}

async fn next_chunk(
    events: &mut worker::EventStream<'_>,
    decoder: &mut Decoder,
    pending: &mut Vec<u8>,
) -> Result<bool> {
    match events.next().await {
        Some(Ok(WebsocketEvent::Message(message))) => {
            if let Some(bytes) = message
                .bytes()
                .filter(|bytes| !bytes.is_empty())
                .or_else(|| {
                    message
                        .text()
                        .and_then(|text| (!text.is_empty()).then_some(text.into_bytes()))
                })
            {
                pending.extend_from_slice(&decoder.decode(&bytes).await?);
            }
            Ok(true)
        }
        Some(Ok(WebsocketEvent::Close(_))) | None => Ok(false),
        Some(Err(err)) => Err(err),
    }
}

fn error_response(message: &str) -> Vec<u8> {
    let mut payload = vec![0x01];
    drop(leb128::write::unsigned(&mut payload, message.len() as u64));
    payload.extend_from_slice(message.as_bytes());
    payload
}

fn send_control(
    outbox: &Outbox,
    muxer: &dyn Muxer,
    windows: Option<&yamux_rs::Windows>,
    sid: u32,
    payload: &[u8],
) {
    let end = payload.len().min(muxer.chunk_limit());
    if let Some(windows) = windows
        && windows.try_acquire(sid, end) == 0
    {
        return;
    }
    let Some(chunk) = payload.get(..end) else {
        return;
    };
    outbox.send(muxer.data_frame(sid, chunk));
}

fn connect_future(sid: u32, target: &SocksAddr) -> Task {
    let host = target.host().into_owned();
    let port = target.port();
    Rc::new(RefCell::new(Box::pin(async move {
        let mut socket = match connect_tcp(&host, port) {
            Ok(socket) => socket,
            Err(err) => return LoopEvent::ConnectFailed(sid, err),
        };
        let opened = with_timeout(CONNECT_TIMEOUT_MS, async {
            socket.opened().await?;
            Ok::<(), Error>(())
        })
        .await;
        if !matches!(opened, Some(Ok(()))) {
            drop(socket.close().await);
        }
        match opened {
            Some(Ok(())) => LoopEvent::Connected(sid, socket),
            Some(Err(err)) => LoopEvent::ConnectFailed(sid, err),
            None => LoopEvent::ConnectFailed(
                sid,
                Error::RustError(format!(
                    "target connection timed out after {CONNECT_TIMEOUT_MS} ms"
                )),
            ),
        }
    })))
}

#[allow(clippy::single_call_fn)]
pub(super) async fn handle(
    websocket: &WebSocket,
    mut events: worker::EventStream<'_>,
    codec: Codec,
    initial: Vec<u8>,
    mode: MuxMode,
) -> Result<()> {
    let Codec {
        inbound: mut decoder,
        outbound: encoder,
    } = codec;
    let mut pending = initial;

    let (muxer, bucket, windows): (
        Rc<dyn Muxer>,
        Option<smux_rs::Bucket>,
        Option<Rc<yamux_rs::Windows>>,
    ) = match mode {
        MuxMode::MuxCool => (Rc::new(mux_cool_rs::Decoder), None, None),
        MuxMode::SingMux => {
            let request = async {
                loop {
                    if pending.len() >= 2 {
                        if let Some((version, protocol)) =
                            pending.first().copied().zip(pending.get(1).copied())
                        {
                            if version > 1 {
                                break Err(Error::RustError(
                                    "unsupported mux session version".into(),
                                ));
                            }
                            if version == 0 {
                                break Ok((protocol, 2));
                            }
                        }
                        if pending.len() >= 3 {
                            if pending.get(2).is_some_and(|padding| *padding != 0) {
                                break Err(Error::RustError(
                                    "mux padding is not supported, set padding: false".into(),
                                ));
                            }
                            if let Some(&protocol) = pending.get(1) {
                                break Ok((protocol, 3));
                            }
                        }
                    }
                    if !next_chunk(&mut events, &mut decoder, &mut pending).await? {
                        break Err(Error::RustError(
                            "tunnel closed before session request".into(),
                        ));
                    }
                }
            };
            let (protocol, consumed) = match request.await {
                Ok(request) => request,
                Err(err) => {
                    tracing::error!("mux: session request failed: {err:?}");
                    drop(websocket.close(Some(1008), Some("invalid mux session")));
                    return Ok(());
                }
            };
            pending.drain(..consumed);
            match protocol {
                0 => {
                    let bucket = smux_rs::Bucket::new();
                    (
                        Rc::new(smux_rs::Decoder::new(bucket.clone())),
                        Some(bucket),
                        None,
                    )
                }
                1 => (
                    Rc::new(yamux_rs::Decoder),
                    None,
                    Some(Rc::new(yamux_rs::Windows::default())),
                ),
                other => {
                    tracing::warn!(
                        "mux: protocol {other} requested; h2mux is not supported, set \
                         `smux.protocol: smux` or `yamux` explicitly"
                    );
                    drop(websocket.close(Some(1008), Some("mux protocol unsupported")));
                    return Ok(());
                }
            }
        }
    };

    let (event_tx, mut event_rx) = futures_channel::mpsc::unbounded();
    let (tx, job_rx) = futures_channel::mpsc::unbounded();
    let outbox = Rc::new(Outbox {
        tx,
        budget: Semaphore::new(OUTBOX_CAPACITY),
    });

    outbox.send(Vec::new());

    let reader_muxer = muxer.clone();
    let reader_bucket = bucket.clone();
    let mut reader_fut: Pin<Box<dyn Future<Output = LoopEvent> + '_>> = Box::pin(async move {
        let mut events = events;
        let mut decoder = decoder;
        let mut pending = pending;
        loop {
            let buffered = pending.len();
            match reader_muxer.decode(&mut pending) {
                Ok(events) if !events.is_empty() => {
                    for event in events {
                        drop(event_tx.unbounded_send(LoopEvent::Raw(event)));
                    }
                    continue;
                }
                Ok(_) if pending.len() < buffered => continue,
                Ok(_) => {}
                Err(err) => {
                    let err = Error::RustError(err.to_string());
                    tracing::error!("mux: tunnel reader failed: {err:?}");
                    return LoopEvent::ReaderDone;
                }
            }
            if let Some(bucket) = &reader_bucket {
                bucket.wait_available().await;
            }
            match next_chunk(&mut events, &mut decoder, &mut pending).await {
                Ok(true) => {}
                Ok(false) => {
                    tracing::info!("mux: tunnel ended");
                    return LoopEvent::ReaderDone;
                }
                Err(err) => {
                    tracing::error!("mux: tunnel reader failed: {err:?}");
                    return LoopEvent::ReaderDone;
                }
            }
        }
    });
    let writer_outbox = outbox.clone();
    let writer_ws = websocket.clone();
    let mut writer_fut = Box::pin(async move {
        let mut encoder = encoder;
        let mut job_rx = job_rx;
        loop {
            let Some(job) = job_rx.next().await else {
                return LoopEvent::WriterDone;
            };
            writer_outbox.budget.add_permits(job.budget);
            let result = match encoder.encode(&job.bytes).await {
                Ok(encoded) if encoded.is_empty() => Ok(()),
                Ok(encoded) => writer_ws.send_with_bytes(&encoded),
                Err(err) => Err(err),
            };
            if let Err(err) = result {
                tracing::error!("mux: tunnel writer failed: {err:?}");
                return LoopEvent::WriterDone;
            }
        }
    });
    let mut reader_done = false;
    let mut writer_done = false;

    let mut streams: HashMap<u32, Stream> = HashMap::new();
    let mut tunnel_done = false;

    let remove_stream = |streams: &mut HashMap<u32, Stream>, sid: u32| {
        if let Some(windows) = &windows {
            windows.close(sid);
        }
        if let Some(stream) = streams.remove(&sid) {
            let mut shared = stream.shared.borrow_mut();
            if let Some(bucket) = &bucket {
                bucket.add(shared.buffered_len);
            }
            shared.close_read();
        }
    };
    let reset_stream = |streams: &mut HashMap<u32, Stream>, sid: u32| {
        outbox.send(muxer.reset_frame(sid));
        remove_stream(streams, sid);
    };

    loop {
        if writer_done {
            break;
        }

        let (event, reader_finished, writer_finished) = poll_fn(|cx| {
            if !reader_done && let Poll::Ready(event) = reader_fut.as_mut().poll(cx) {
                return Poll::Ready((event, true, false));
            }
            if !writer_done && let Poll::Ready(event) = writer_fut.as_mut().poll(cx) {
                return Poll::Ready((event, false, true));
            }
            if let Poll::Ready(event) = event_rx.poll_next_unpin(cx) {
                return Poll::Ready((event.unwrap_or(LoopEvent::ReaderDone), false, false));
            }
            for stream in streams.values() {
                if let StreamPhase::Active { fut } = &stream.phase
                    && let Poll::Ready(event) = fut.borrow_mut().as_mut().poll(cx)
                {
                    return Poll::Ready((event, false, false));
                }
            }
            Poll::Pending
        })
        .await;
        if reader_finished {
            reader_done = true;
        }
        if writer_finished {
            writer_done = true;
        }
        match event {
            LoopEvent::Raw(Event::Open { sid, target }) => {
                if streams.contains_key(&sid) {
                    continue;
                }
                if let Some(windows) = &windows {
                    outbox.send(windows.open(sid));
                }
                let shared: Shared = Rc::default();
                match target {
                    Some(target) if target.is_routable() => {
                        tracing::info!("mux: stream {sid} -> {target}");
                        streams.insert(
                            sid,
                            Stream {
                                shared,
                                phase: StreamPhase::Active {
                                    fut: connect_future(sid, &target),
                                },
                            },
                        );
                    }
                    Some(_) => {
                        tracing::warn!("mux: stream {sid} has an invalid target");
                        reset_stream(&mut streams, sid);
                    }
                    None => {
                        streams.insert(
                            sid,
                            Stream {
                                shared,
                                phase: StreamPhase::Preparing,
                            },
                        );
                    }
                }
            }
            LoopEvent::Raw(Event::Data { sid, data }) => {
                let overflow = streams.get(&sid).is_some_and(|stream| {
                    let mut shared = stream.shared.borrow_mut();
                    if shared.buffered_len + data.len() > 4 * 1024 * 1024 {
                        return true;
                    }
                    shared.buffered_len += data.len();
                    shared.buffer.push_back(data);
                    if let Some(waker) = shared.waker.take() {
                        waker.wake();
                    }
                    false
                });
                if overflow {
                    tracing::warn!("mux: stream {sid} buffer overflow, resetting");
                    reset_stream(&mut streams, sid);
                }
            }
            LoopEvent::Raw(Event::Eof { sid }) => {
                if let Some(stream) = streams.get(&sid) {
                    stream.shared.borrow_mut().close_read();
                }
            }
            LoopEvent::Raw(Event::Reset { sid }) => {
                remove_stream(&mut streams, sid);
            }
            LoopEvent::Raw(Event::Window { sid, delta }) => {
                if let Some(windows) = &windows {
                    windows.grant(sid, delta);
                }
            }
            LoopEvent::Raw(Event::Ping { value }) => {
                if let Some(frame) = muxer.ping_ack(value) {
                    outbox.send(frame);
                }
            }
            LoopEvent::Raw(Event::Reject { sid }) => {
                tracing::info!("mux: stream {sid} requests udp, rejecting");
                reset_stream(&mut streams, sid);
            }
            LoopEvent::Raw(Event::Closed) | LoopEvent::ReaderDone => {
                tunnel_done = true;
                streams.clear();
            }
            LoopEvent::WriterDone => {}
            LoopEvent::Connected(sid, socket) => {
                let Some(stream) = streams.get_mut(&sid) else {
                    continue;
                };
                let shared = Rc::clone(&stream.shared);
                let (outbox, muxer, bucket, windows) = (
                    outbox.clone(),
                    muxer.clone(),
                    bucket.clone(),
                    windows.clone(),
                );
                stream.phase = StreamPhase::Active {
                    fut: Rc::new(RefCell::new(Box::pin(async move {
                        LoopEvent::PumpDone(
                            sid,
                            pump_task(sid, socket, shared, outbox, muxer, bucket, windows).await,
                        )
                    }))),
                };
            }
            LoopEvent::ConnectFailed(sid, err) => {
                tracing::warn!("mux: stream {sid} connect failed: {err:?}");
                if mode == MuxMode::SingMux {
                    send_control(
                        &outbox,
                        muxer.as_ref(),
                        windows.as_deref(),
                        sid,
                        &error_response("connect failed"),
                    );
                }
                reset_stream(&mut streams, sid);
            }
            LoopEvent::PumpDone(sid, result) => match result {
                Ok((up, down)) => {
                    tracing::info!("mux: stream {sid} finished (up={up}, down={down})");
                    remove_stream(&mut streams, sid);
                }
                Err(err) => {
                    tracing::warn!("mux: stream {sid} pump failed: {err}");
                    reset_stream(&mut streams, sid);
                }
            },
        }

        let mut resolved: Vec<(u32, Result<(bool, SocksAddr)>)> = Vec::new();
        streams.retain(|sid, stream| {
            if !matches!(stream.phase, StreamPhase::Preparing) {
                return true;
            }
            let mut shared = stream.shared.borrow_mut();
            if shared.buffered_len == 0 {
                if shared.eof {
                    resolved.push((
                        *sid,
                        Err(Error::RustError("stream closed before request".into())),
                    ));
                }
                return true;
            }
            if shared.buffer.len() > 1 {
                let framed: Vec<u8> = shared.buffer.iter().flatten().copied().collect();
                shared.buffer = vec![framed].into();
            }
            let eof = shared.eof;
            let Some(framed) = shared.buffer.front_mut() else {
                resolved.push((
                    *sid,
                    Err(Error::RustError("invalid mux stream buffer state".into())),
                ));
                return false;
            };
            let parsed =
                framed
                    .first()
                    .copied()
                    .zip(framed.get(2..))
                    .and_then(|(first, payload)| match SocksAddr::parse_socks(payload) {
                        Ok((target, consumed)) => Some(Ok(((first & 0x01 != 0, target), consumed))),
                        Err(ParseError::Truncated) => None,
                        Err(ParseError::Invalid(message)) => {
                            Some(Err(Error::RustError(message.into())))
                        }
                    });
            let parsed = parsed.map(|result| {
                result.map(|((is_udp, target), consumed)| {
                    framed.drain(..2 + consumed);
                    (is_udp, target, consumed)
                })
            });
            match parsed {
                Some(Ok((udp, target, consumed))) => {
                    shared.buffered_len -= 2 + consumed;
                    if let Some(bucket) = &bucket {
                        bucket.add(2 + consumed);
                    }
                    if let Some(frame) = windows
                        .as_ref()
                        .and_then(|windows| windows.recv_forwarded(*sid, 2 + consumed))
                    {
                        outbox.send(frame);
                    }
                    resolved.push((*sid, Ok((udp, target))));
                }
                Some(Err(err)) => resolved.push((*sid, Err(err))),
                None if eof => {
                    resolved.push((*sid, Err(Error::RustError("truncated mux request".into()))))
                }
                None if framed.len() > 2 * 1024 => {
                    resolved.push((*sid, Err(Error::RustError("mux request too large".into()))))
                }
                None => {}
            }
            true
        });
        for (sid, outcome) in resolved {
            match outcome {
                Ok((udp, target)) if udp || !target.is_routable() => {
                    tracing::warn!(
                        "mux: stream {sid} requests {}",
                        if udp { "udp" } else { "an invalid target" }
                    );
                    if mode == MuxMode::SingMux {
                        send_control(
                            &outbox,
                            muxer.as_ref(),
                            windows.as_deref(),
                            sid,
                            &error_response(if udp {
                                "udp is not supported"
                            } else {
                                "invalid target"
                            }),
                        );
                    }
                    reset_stream(&mut streams, sid);
                }
                Ok((_, target)) => {
                    tracing::info!("mux: stream {sid} -> {target}");
                    if let Some(stream) = streams.get_mut(&sid) {
                        stream.phase = StreamPhase::Active {
                            fut: connect_future(sid, &target),
                        };
                    }
                }
                Err(err) => {
                    tracing::warn!("mux: stream {sid} request failed: {err:?}");
                    if mode == MuxMode::SingMux {
                        send_control(
                            &outbox,
                            muxer.as_ref(),
                            windows.as_deref(),
                            sid,
                            &error_response("invalid request"),
                        );
                    }
                    reset_stream(&mut streams, sid);
                }
            }
        }

        if tunnel_done && streams.is_empty() {
            break;
        }
    }

    drop(websocket.close(None, None::<String>));
    Ok(())
}

#[allow(clippy::single_call_fn)]
async fn pump_task(
    sid: u32,
    socket: worker::Socket,
    shared: Shared,
    outbox: Rc<Outbox>,
    muxer: Rc<dyn Muxer>,
    bucket: Option<smux_rs::Bucket>,
    windows: Option<Rc<yamux_rs::Windows>>,
) -> std::io::Result<(u64, u64)> {
    let (mut rd, mut wr) = tokio::io::split(socket);
    let mut buf = vec![0_u8; 64 * 1024];

    let read_half = async {
        let mut down = 0_u64;
        loop {
            let n = rd.read(&mut buf).await?;
            if n == 0 {
                outbox.send(muxer.eof_frame(sid));
                return Ok::<u64, std::io::Error>(down);
            }
            let bytes = buf.get(..n).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid socket read length",
                )
            })?;
            let mut data = bytes;
            while !data.is_empty() {
                let mut chunk = data.len().min(muxer.chunk_limit());
                if let Some(windows) = windows.as_deref() {
                    chunk = chunk.min(windows.acquire(sid, chunk).await);
                    if chunk == 0 {
                        break;
                    }
                }
                let (head, tail) = data.split_at(chunk);
                outbox.send_framed(muxer.data_frame(sid, head)).await;
                data = tail;
            }
            down += n as u64;
        }
    };
    let write_half = async {
        let mut up = 0_u64;
        loop {
            let has_data = poll_fn(|cx| {
                let mut shared = shared.borrow_mut();
                if shared.buffered_len > 0 {
                    return Poll::Ready(true);
                }
                if shared.eof {
                    return Poll::Ready(false);
                }
                shared.waker = Some(cx.waker().clone());
                Poll::Pending
            })
            .await;
            if !has_data {
                wr.shutdown().await?;
                return Ok::<u64, std::io::Error>(up);
            }
            let chunk = {
                let mut shared = shared.borrow_mut();
                let data = shared.buffer.pop_front().ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "buffer length does not match stream data",
                    )
                })?;
                shared.buffered_len -= data.len();
                if let Some(bucket) = &bucket {
                    bucket.add(data.len());
                }
                if let Some(frame) = windows
                    .as_ref()
                    .and_then(|windows| windows.recv_forwarded(sid, data.len()))
                {
                    outbox.send(frame);
                }
                data
            };
            wr.write_all(&chunk).await?;
            up += chunk.len() as u64;
        }
    };
    match select(pin!(read_half), pin!(write_half)).await {
        Either::Left((result, write_half)) => {
            let down = result?;
            let up = write_half.await?;
            Ok((up, down))
        }
        Either::Right((result, read_half)) => {
            let up = result?;
            let down = read_half.await?;
            Ok((up, down))
        }
    }
}
