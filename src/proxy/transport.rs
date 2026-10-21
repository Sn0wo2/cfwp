use std::borrow::Cow;
use std::cell::Cell;
use std::rc::Rc;

use futures_util::StreamExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt, split};
use worker::{Error, Result, Socket, WebSocket, WebsocketEvent};

use super::outbound::ProxyPlan;
use super::protocol::{Codec, Decoder, Encoder, InitialRequest};
use super::util::decode_message;
use crate::dns::DnsService;

pub(super) trait InboundStream {
    async fn decode<'a>(&mut self, bytes: &'a [u8]) -> Result<Cow<'a, [u8]>>;
}

pub(super) trait OutboundStream {
    async fn encode<'a>(&mut self, bytes: &'a [u8]) -> Result<Cow<'a, [u8]>>;
}

pub(super) trait ProtocolStream {
    type Inbound: InboundStream;
    type Outbound: OutboundStream;

    fn split(&mut self) -> (&mut Self::Inbound, &mut Self::Outbound);
}

impl ProtocolStream for Codec {
    type Inbound = Decoder;
    type Outbound = Encoder;

    fn split(&mut self) -> (&mut Self::Inbound, &mut Self::Outbound) {
        (&mut self.inbound, &mut self.outbound)
    }
}

#[allow(clippy::single_call_fn)]
pub(super) async fn pipe<C: ProtocolStream>(
    websocket: &WebSocket,
    events: &mut worker::EventStream<'_>,
    socket: &mut Socket,
    codec: &mut C,
) -> Result<(bool, bool)> {
    let (mut reader_socket, mut writer_socket) = split(socket);
    let (decoder, encoder) = codec.split();
    let websocket = websocket.clone();
    let client_data = Rc::new(Cell::new(false));
    let client_data_writer = client_data.clone();
    let reader = async move {
        let mut buf = vec![0_u8; 16 * 1024];
        let mut has_data = false;
        loop {
            let read = reader_socket.read(&mut buf).await?;
            if read == 0 {
                break;
            }
            has_data = true;
            let bytes = buf
                .get(..read)
                .ok_or_else(|| Error::RustError("invalid socket read length".into()))?;
            websocket.send_with_bytes(encoder.encode(bytes).await?)?;
        }
        Ok::<bool, Error>(has_data)
    };
    let writer = async move {
        while let Some(event) = events.next().await {
            match event? {
                WebsocketEvent::Message(message) => {
                    if let Some(payload) = decode_message(message) {
                        let decoded = decoder.decode(&payload).await?;
                        if !decoded.is_empty() {
                            client_data_writer.set(true);
                            writer_socket.write_all(&decoded).await?;
                            writer_socket.flush().await?;
                        }
                    }
                }
                WebsocketEvent::Close(_) => break,
            }
        }

        writer_socket.shutdown().await?;
        Ok::<(), Error>(())
    };

    match futures_util::future::select(Box::pin(reader), Box::pin(writer)).await {
        futures_util::future::Either::Left((result, _)) => {
            result.map(|has_data| (has_data, client_data.get()))
        }
        futures_util::future::Either::Right((result, _)) => {
            result?;
            Ok((true, client_data.get()))
        }
    }
}

#[allow(clippy::single_call_fn)]
pub(super) async fn route(
    websocket: &WebSocket,
    events: &mut worker::EventStream<'_>,
    request: &mut InitialRequest,
    plan: &ProxyPlan,
    dns: &DnsService,
) -> Result<()> {
    tracing::info!(
        "session: connecting final outbound {} (port={})",
        plan.kind_name(),
        request.port
    );
    let mut socket = plan.connect(request, dns).await?;
    let result = pipe(websocket, events, &mut socket, &mut request.codec).await;
    drop(socket.close().await);
    result?;
    websocket.close(None, None::<String>)?;
    Ok(())
}
