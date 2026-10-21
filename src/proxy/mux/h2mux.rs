use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures_util::future::{Either, select};
use futures_util::{FutureExt, StreamExt};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, split};
use worker::{Error, Result, Socket, WebSocket, WebsocketEvent};

use super::super::outbound::ProxyPlan;
use super::super::protocol::Codec;
use super::super::transport::{InboundStream, OutboundStream};
use super::super::util::decode_message;
use crate::dns::DnsService;

struct TargetSocket(Socket);

impl AsyncRead for TargetSocket {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
    }
}

impl AsyncWrite for TargetSocket {
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

impl Drop for TargetSocket {
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
    plan: ProxyPlan,
    dns: DnsService,
) -> Result<()> {
    let Codec {
        inbound: mut decoder,
        outbound: mut encoder,
    } = codec;
    let (server_io, adapter_io) = tokio::io::duplex(64 * 1024);
    let (mut adapter_reader, mut adapter_writer) = split(adapter_io);
    let input = Box::pin(async move {
        if !initial.is_empty() {
            adapter_writer
                .write_all(&initial)
                .await
                .map_err(|error| Error::RustError(error.to_string()))?;
        }
        loop {
            match events.next().await {
                Some(Ok(WebsocketEvent::Message(message))) => {
                    if let Some(bytes) = decode_message(message) {
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
    });

    let output_websocket = websocket.clone();
    let output = Box::pin(async move {
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
                .ok_or_else(|| Error::RustError("invalid h2mux output length".into()))?;
            let encoded = encoder.encode(bytes).await?;
            if !encoded.is_empty() {
                output_websocket.send_with_bytes(&encoded)?;
            }
        }
    });

    let connector = move |host: String, port: u16| {
        let plan = plan.clone();
        let dns = dns.clone();
        async move {
            plan.connect_address(&host, port, &dns)
                .await
                .map(TargetSocket)
                .map_err(|error| io::Error::other(error.to_string()))
        }
    };
    let session = Box::pin(h2mux_rs::serve(server_io, connector));
    let adapters = async move {
        match select(input, output).await {
            Either::Left((result, output)) => {
                result?;
                output.await
            }
            Either::Right((result, _input)) => result,
        }
    };
    match select(session, Box::pin(adapters)).await {
        Either::Left((result, adapters)) => {
            result.map_err(|error| Error::RustError(error.to_string()))?;
            adapters.await?;
        }
        Either::Right((result, _session)) => result?,
    }
    websocket.close(None, None::<String>)?;
    Ok(())
}
