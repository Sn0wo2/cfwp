use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures_util::StreamExt;
use futures_util::future::{Either, FutureExt, select};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use worker::{Error, Result, Socket, WebSocket, WebsocketEvent};

use super::inbound::codec::Codec;
use super::outbound::ProxyPlan;
use crate::dns::DnsService;

struct MuxSocket(Socket);

impl AsyncRead for MuxSocket {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
    }
}

impl AsyncWrite for MuxSocket {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
}

impl Drop for MuxSocket {
    fn drop(&mut self) {
        drop(self.0.close().now_or_never());
    }
}

#[allow(clippy::single_call_fn)]
pub(super) async fn handle(
    websocket: &WebSocket,
    mut events: worker::EventStream<'_>,
    codec: Codec,
    initial: Vec<u8>,
    mode: mux_core::Mode,
    plan: ProxyPlan,
    dns: DnsService,
) -> Result<()> {
    let (server_io, adapter_io) = tokio::io::duplex(64 * 1024);
    let Codec {
        inbound: mut decoder,
        outbound: mut encoder,
    } = codec;
    let (mut adapter_reader, mut adapter_writer) = tokio::io::split(adapter_io);
    let input = async move {
        if !initial.is_empty() {
            adapter_writer
                .write_all(&initial)
                .await
                .map_err(|error| Error::RustError(error.to_string()))?;
        }
        loop {
            match events.next().await {
                Some(Ok(WebsocketEvent::Message(message))) => {
                    if let Some(bytes) = super::util::decode_message(message) {
                        let decoded = decoder.decode(&bytes).await?;
                        adapter_writer
                            .write_all(&decoded)
                            .await
                            .map_err(|error| Error::RustError(error.to_string()))?;
                    }
                }
                Some(Ok(WebsocketEvent::Close(_))) | None => {
                    adapter_writer
                        .shutdown()
                        .await
                        .map_err(|error| Error::RustError(error.to_string()))?;
                    return Ok(());
                }
                Some(Err(error)) => return Err(error),
            }
        }
    };
    let output_websocket = websocket.clone();
    let output = async move {
        let mut buffer = vec![0_u8; 16 * 1024];
        loop {
            let length = adapter_reader
                .read(&mut buffer)
                .await
                .map_err(|error| Error::RustError(error.to_string()))?;
            if length == 0 {
                return Ok::<(), Error>(());
            }
            let bytes = buffer
                .get(..length)
                .ok_or_else(|| Error::RustError("invalid mux output length".into()))?;
            let encoded = encoder.encode(bytes).await?;
            if !encoded.is_empty() {
                output_websocket.send_with_bytes(&encoded)?;
            }
        }
    };
    let session = mux_core::serve(
        server_io,
        mode,
        mux_core::Config::default(),
        move |host: String, port| {
            let plan = plan.clone();
            let dns = dns.clone();
            async move {
                plan.connect(&host, port, &[], &dns)
                    .await
                    .map(MuxSocket)
                    .map_err(|error| io::Error::other(error.to_string()))
            }
        },
    );
    futures_util::pin_mut!(input, output);
    let adapters = async move {
        match select(input, output).await {
            Either::Left((result, output)) => {
                result?;
                output.await
            }
            Either::Right((result, _input)) => result,
        }
    };
    futures_util::pin_mut!(session, adapters);
    match select(session, adapters).await {
        Either::Left((Err(error), _adapters))
            if matches!(
                error.kind(),
                io::ErrorKind::InvalidData
                    | io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::Unsupported
            ) =>
        {
            let message = if error.kind() == io::ErrorKind::Unsupported {
                "mux protocol unsupported"
            } else {
                "invalid mux session"
            };
            drop(websocket.close(Some(1008), Some(message)));
        }
        Either::Left((result, adapters)) => {
            result.map_err(|error| Error::RustError(error.to_string()))?;
            adapters.await?;
        }
        Either::Right((result, _session)) => result?,
    }
    websocket.close(None, None::<String>)?;
    Ok(())
}
