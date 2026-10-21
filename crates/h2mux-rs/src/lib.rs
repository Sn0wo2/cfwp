use std::future::Future;
use std::io;
use std::task::Poll;

use bytes::Bytes;
use futures_util::StreamExt;
use futures_util::future::{Either, poll_fn, select};
use futures_util::stream::FuturesUnordered;
use http::{Request, Response, StatusCode};
use socksaddr::{ParseError, SocksAddr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, split};

const MAX_CONCURRENT_STREAMS: u32 = 64;
const MAX_STREAM_REQUEST_SIZE: usize = 2 + 259;

type AcceptedRequest = (Request<h2::RecvStream>, h2::server::SendResponse<Bytes>);
type AcceptResult = Option<Result<AcceptedRequest, h2::Error>>;

enum DriverEvent {
    Accepted(AcceptResult),
    Stream(io::Result<()>),
}

pub async fn serve<I, C, F, S>(io: I, connector: C) -> io::Result<()>
where
    I: AsyncRead + AsyncWrite + Unpin,
    C: Fn(String, u16) -> F + Clone + 'static,
    F: Future<Output = io::Result<S>> + 'static,
    S: AsyncRead + AsyncWrite + Unpin + 'static,
{
    let mut builder = h2::server::Builder::new();
    builder.max_concurrent_streams(MAX_CONCURRENT_STREAMS);
    let mut connection = builder
        .handshake::<_, Bytes>(io)
        .await
        .map_err(|error| io::Error::other(error.to_string()))?;
    let mut stream_tasks = FuturesUnordered::new();

    loop {
        let event = poll_fn(|cx| {
            if !stream_tasks.is_empty()
                && let Poll::Ready(Some(result)) = stream_tasks.poll_next_unpin(cx)
            {
                return Poll::Ready(DriverEvent::Stream(result));
            }
            if let Poll::Ready(accepted) = connection.poll_accept(cx) {
                return Poll::Ready(DriverEvent::Accepted(accepted));
            }
            Poll::Pending
        })
        .await;

        match event {
            DriverEvent::Stream(Ok(())) => {}
            DriverEvent::Stream(Err(error)) => {
                tracing::warn!("h2mux: stream failed: {error:?}");
            }
            DriverEvent::Accepted(Some(Ok((request, mut respond)))) => {
                if stream_tasks.len() >= MAX_CONCURRENT_STREAMS as usize {
                    respond.send_reset(h2::Reason::REFUSED_STREAM);
                    continue;
                }
                let mut response = Response::new(());
                *response.status_mut() = StatusCode::OK;
                let send = respond
                    .send_response(response, false)
                    .map_err(|error| io::Error::other(error.to_string()))?;
                let connector = connector.clone();
                stream_tasks.push(Box::pin(async move {
                    let mut send = send;
                    let mut receive = request.into_body();
                    let request = async {
                        let mut request = Vec::new();
                        loop {
                            let Some(data) = receive.data().await else {
                                return Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "h2mux stream ended before its request header",
                                ));
                            };
                            let data = data.map_err(|error| io::Error::other(error.to_string()))?;
                            request.extend_from_slice(&data);
                            if request.len() >= 2 {
                                let flags = request
                                    .get(..2)
                                    .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
                                    .map(u16::from_be_bytes)
                                    .ok_or_else(|| {
                                        io::Error::new(
                                            io::ErrorKind::InvalidData,
                                            "invalid h2mux stream flags",
                                        )
                                    })?;
                                let address_bytes = request.get(2..).ok_or_else(|| {
                                    io::Error::new(
                                        io::ErrorKind::InvalidData,
                                        "invalid h2mux stream address",
                                    )
                                })?;
                                match SocksAddr::parse_socks(address_bytes) {
                                    Ok((target, address_length)) => {
                                        let consumed = (2 + address_length)
                                            .saturating_sub(request.len() - data.len());
                                        if consumed > 0 {
                                            receive
                                                .flow_control()
                                                .release_capacity(consumed)
                                                .map_err(|error| {
                                                    io::Error::other(error.to_string())
                                                })?;
                                        }
                                        return Ok((flags, target, data.slice(consumed..)));
                                    }
                                    Err(ParseError::Truncated) => {}
                                    Err(ParseError::Invalid(message)) => {
                                        return Err(io::Error::new(
                                            io::ErrorKind::InvalidData,
                                            message,
                                        ));
                                    }
                                }
                            }
                            receive
                                .flow_control()
                                .release_capacity(data.len())
                                .map_err(|error| io::Error::other(error.to_string()))?;
                            if request.len() >= MAX_STREAM_REQUEST_SIZE {
                                return Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "h2mux stream request header is too large",
                                ));
                            }
                        }
                    }
                    .await;
                    let (flags, target, initial_data) = match request {
                        Ok(request) => request,
                        Err(error) => {
                            send.send_data(Bytes::from(error_response(&error.to_string())), true)
                                .map_err(|error| io::Error::other(error.to_string()))?;
                            return Ok(());
                        }
                    };
                    if flags & 1 != 0 {
                        send.send_data(Bytes::from(error_response("UDP is unsupported")), true)
                            .map_err(|error| io::Error::other(error.to_string()))?;
                        return Ok(());
                    }
                    if flags & !1 != 0 {
                        send.send_data(
                            Bytes::from(error_response("unsupported stream flags")),
                            true,
                        )
                        .map_err(|error| io::Error::other(error.to_string()))?;
                        return Ok(());
                    }
                    if !target.is_routable() {
                        send.send_data(Bytes::from(error_response("invalid stream target")), true)
                            .map_err(|error| io::Error::other(error.to_string()))?;
                        return Ok(());
                    }
                    tracing::info!("h2mux: connecting stream to {target}");
                    let socket = match connector(target.host().into_owned(), target.port()).await {
                        Ok(socket) => socket,
                        Err(error) => {
                            send.send_data(Bytes::from(error_response(&error.to_string())), true)
                                .map_err(|error| io::Error::other(error.to_string()))?;
                            return Ok(());
                        }
                    };
                    send.send_data(Bytes::from_static(&[0]), false)
                        .map_err(|error| io::Error::other(error.to_string()))?;

                    let (mut reader, mut writer) = split(socket);
                    let read_future = async move {
                        let mut buffer = vec![0_u8; 16 * 1024];
                        loop {
                            let length = reader.read(&mut buffer).await?;
                            if length == 0 {
                                send.send_data(Bytes::new(), true)
                                    .map_err(|error| io::Error::other(error.to_string()))?;
                                return Ok(());
                            }
                            let bytes = buffer.get(..length).ok_or_else(|| {
                                io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "invalid target read length",
                                )
                            })?;
                            let data = Bytes::copy_from_slice(bytes);
                            let mut offset = 0;
                            while offset < data.len() {
                                send.reserve_capacity(data.len() - offset);
                                let capacity = poll_fn(|cx| send.poll_capacity(cx))
                                    .await
                                    .ok_or_else(|| {
                                        io::Error::new(
                                            io::ErrorKind::BrokenPipe,
                                            "h2mux response stream closed",
                                        )
                                    })?
                                    .map_err(|error| io::Error::other(error.to_string()))?;
                                if capacity == 0 {
                                    return Err(io::Error::new(
                                        io::ErrorKind::WriteZero,
                                        "h2mux response stream has no available capacity",
                                    ));
                                }
                                let end = offset + capacity.min(data.len() - offset);
                                send.send_data(data.slice(offset..end), false)
                                    .map_err(|error| io::Error::other(error.to_string()))?;
                                offset = end;
                            }
                        }
                    };
                    let write_future = async move {
                        if !initial_data.is_empty() {
                            writer.write_all(&initial_data).await?;
                            receive
                                .flow_control()
                                .release_capacity(initial_data.len())
                                .map_err(|error| io::Error::other(error.to_string()))?;
                        }
                        while let Some(data) = receive.data().await {
                            let data = data.map_err(|error| io::Error::other(error.to_string()))?;
                            let length = data.len();
                            if length > 0 {
                                writer.write_all(&data).await?;
                                receive
                                    .flow_control()
                                    .release_capacity(length)
                                    .map_err(|error| io::Error::other(error.to_string()))?;
                            }
                        }
                        writer.shutdown().await
                    };
                    futures_util::pin_mut!(read_future, write_future);
                    match select(read_future, write_future).await {
                        Either::Left((result, write_future)) => {
                            result?;
                            write_future.await
                        }
                        Either::Right((result, read_future)) => {
                            result?;
                            read_future.await
                        }
                    }
                }));
            }
            DriverEvent::Accepted(Some(Err(error))) => {
                return Err(io::Error::other(error.to_string()));
            }
            DriverEvent::Accepted(None) => return Ok(()),
        }
    }
}

pub fn error_response(message: &str) -> Vec<u8> {
    let mut payload = vec![0x01];
    let mut length = message.len() as u64;
    loop {
        let byte = (length & 0x7f) as u8;
        length >>= 7;
        payload.push(if length == 0 { byte } else { byte | 0x80 });
        if length == 0 {
            break;
        }
    }
    payload.extend_from_slice(message.as_bytes());
    payload
}
