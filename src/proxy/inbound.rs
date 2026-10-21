use std::net::IpAddr;

use base64::Engine;
use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
use futures_util::StreamExt;
use worker::{Context, Request, Response, Result, WebSocketPair, WebsocketEvent};

use super::outbound::ProxyPlan;
use super::protocol::InitialRequest;
use super::transport::{self, InboundStream, OutboundStream};

#[allow(clippy::single_call_fn)]
pub(crate) async fn handle(
    config: &crate::config::Config,
    req: Request,
    ctx: Context,
) -> Result<Response> {
    let request_url = req.url()?;
    let inbounds = config
        .inbounds
        .iter()
        .filter(|inbound| inbound.accepts_path(request_url.path()))
        .cloned()
        .collect::<Vec<_>>();
    if inbounds.is_empty() {
        return Response::error("Not Found", 404);
    }
    let colo = req.cf().map(|cf| cf.colo().to_lowercase());
    let plan = ProxyPlan::from_config(config, colo.as_deref())?;
    let early_data = req
        .headers()
        .get("sec-websocket-protocol")
        .ok()
        .flatten()
        .unwrap_or_default();
    let client_ip = req
        .headers()
        .get("CF-Connecting-IP")
        .ok()
        .flatten()
        .and_then(|value| value.parse::<IpAddr>().ok());
    let pair = WebSocketPair::new()?;
    pair.server
        .as_ref()
        .set_binary_type(web_sys::BinaryType::Arraybuffer);
    pair.server.accept()?;
    let websocket = pair.server;
    let dns = config.dns.clone();

    ctx.wait_until(async move {
        tracing::info!("session: websocket accepted");
        let cleanup_websocket = websocket.clone();
        if let Err(err) = async move {
            let mut events = websocket.events()?;
            let mut initial = if early_data.is_empty() {
                Vec::new()
            } else {
                URL_SAFE_NO_PAD
                    .decode(early_data.as_bytes())
                    .or_else(|_| URL_SAFE.decode(early_data.as_bytes()))
                    .unwrap_or_else(|err| {
                        tracing::error!("session: ignoring invalid early data: {err}");
                        Vec::new()
                    })
            };
            if !initial.is_empty() {
                tracing::info!("session: early data received ({} bytes)", initial.len());
            }
            while initial.is_empty() {
                match events.next().await {
                    Some(event) => match event? {
                        WebsocketEvent::Message(message) => {
                            if let Some(payload) = transport::decode_message(message) {
                                tracing::info!(
                                    "session: first websocket message ({} bytes)",
                                    payload.len()
                                );
                                initial = payload;
                            }
                        }
                        WebsocketEvent::Close(_) => {
                            tracing::info!("session: websocket closed before first message");
                            break;
                        }
                    },
                    None => break,
                }
            }
            if initial.is_empty() {
                tracing::info!("session: closed without an initial payload");
                websocket.close(None, None::<String>)?;
                return Ok(());
            }

            const MAX_INITIAL_HEADER: usize = 64 * 1024;
            tracing::info!("session: parsing initial payload ({} bytes)", initial.len());
            let mut trailing = if initial.len() > MAX_INITIAL_HEADER {
                initial.split_off(MAX_INITIAL_HEADER)
            } else {
                Vec::new()
            };
            let mut request = match loop {
                match InitialRequest::parse(&initial, &inbounds).await {
                    Ok(Some(mut request)) => {
                        if !trailing.is_empty() {
                            let decoded = request.codec.inbound.decode(&trailing).await?;
                            request.payload.extend_from_slice(&decoded);
                        }
                        break Ok(request);
                    }
                    Ok(None) if initial.len() < MAX_INITIAL_HEADER => match events.next().await {
                        Some(Ok(WebsocketEvent::Message(message))) => {
                            if let Some(bytes) = transport::decode_message(message) {
                                tracing::info!("session: continued header ({} bytes)", bytes.len());
                                let remaining = MAX_INITIAL_HEADER - initial.len();
                                if bytes.len() > remaining {
                                    let header = bytes.get(..remaining).ok_or_else(|| {
                                        worker::Error::RustError(
                                            "invalid initial request boundary".into(),
                                        )
                                    })?;
                                    let payload = bytes.get(remaining..).ok_or_else(|| {
                                        worker::Error::RustError(
                                            "invalid initial request boundary".into(),
                                        )
                                    })?;
                                    initial.extend_from_slice(header);
                                    trailing.extend_from_slice(payload);
                                } else {
                                    initial.extend(bytes);
                                }
                            }
                        }
                        _ => {
                            break Err(worker::Error::RustError("incomplete request".into()));
                        }
                    },
                    Ok(None) => {
                        break Err(worker::Error::RustError("request too large".into()));
                    }
                    Err(err) => break Err(err),
                }
            } {
                Ok(request) => request,
                Err(err) => {
                    tracing::error!("session: request parse failed: {err:?}");
                    drop(websocket.close(Some(1008), Some("invalid request")));
                    return Err(err);
                }
            };
            tracing::info!("session: request parsed (port={})", request.port);

            let hostname = request.hostname.as_str();
            if request.port == 0
                || (hostname.parse::<IpAddr>().is_err()
                    && !(hostname.is_ascii()
                        && hostname.len() <= 254
                        && hostname
                            .strip_suffix('.')
                            .unwrap_or(hostname)
                            .split('.')
                            .all(|label| {
                                !label.is_empty()
                                    && label.len() <= 63
                                    && label
                                        .as_bytes()
                                        .first()
                                        .is_some_and(u8::is_ascii_alphanumeric)
                                    && label
                                        .as_bytes()
                                        .last()
                                        .is_some_and(u8::is_ascii_alphanumeric)
                                    && label
                                        .bytes()
                                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                            })))
            {
                tracing::error!("session: invalid target authority");
                drop(websocket.close(Some(1008), Some("invalid request")));
                return Err(worker::Error::RustError("invalid target authority".into()));
            }

            if request.hostname == "speed.cloudflare.com"
                || request.hostname.ends_with(".speed.cloudflare.com")
            {
                websocket.close(Some(1008), Some("blocked"))?;
                return Ok(());
            }

            let udp_only = request.is_udp && !request.is_dns_request();
            if udp_only {
                tracing::info!("session: UDP request unsupported");
                websocket.close(Some(1003), Some("udp unsupported"))?;
                return Ok(());
            }

            if request.is_dns_request() {
                tracing::info!("session: forwarding DNS request");
                let mut pending = std::mem::take(&mut request.payload);
                loop {
                    while pending.len() >= 2 {
                        let length_bytes = pending
                            .get(..2)
                            .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
                            .ok_or_else(|| {
                                worker::Error::RustError("invalid DNS packet frame".into())
                            })?;
                        let length = usize::from(u16::from_be_bytes(length_bytes));
                        if length == 0 {
                            return Err(worker::Error::RustError(
                                "invalid DNS packet frame".into(),
                            ));
                        }
                        let frame_end = length.checked_add(2).ok_or_else(|| {
                            worker::Error::RustError("invalid DNS packet frame".into())
                        })?;
                        if pending.len() < frame_end {
                            break;
                        }

                        let query = pending.get(2..frame_end).ok_or_else(|| {
                            worker::Error::RustError("invalid DNS packet frame".into())
                        })?;
                        let response = dns
                            .exchange_prepared(dns.prepare(query, client_ip)?)
                            .await?;
                        let response_length = u16::try_from(response.len()).map_err(|_| {
                            worker::Error::RustError("DNS response too large".into())
                        })?;
                        let mut framed = Vec::with_capacity(response.len() + 2);
                        framed.extend_from_slice(&response_length.to_be_bytes());
                        framed.extend_from_slice(&response);
                        websocket.send_with_bytes(request.codec.outbound.encode(&framed).await?)?;
                        pending.drain(..length + 2);
                    }

                    match events.next().await {
                        Some(Ok(WebsocketEvent::Message(message))) => {
                            if let Some(bytes) = transport::decode_message(message) {
                                pending.extend_from_slice(
                                    &request.codec.inbound.decode(&bytes).await?,
                                );
                            }
                        }
                        Some(Ok(WebsocketEvent::Close(_))) | None => {
                            if pending.is_empty() {
                                websocket.close(None, None::<String>)?;
                                return Ok(());
                            }
                            return Err(worker::Error::RustError("incomplete DNS packet".into()));
                        }
                        Some(Err(err)) => return Err(err),
                    }
                }
            }

            if let Some(mode) = request.mux_mode() {
                tracing::info!("session: mux session accepted ({mode:?})");
                let InitialRequest { payload, codec, .. } = request;
                return super::mux::handle(
                    &websocket,
                    events,
                    codec,
                    payload,
                    mode,
                    plan,
                    dns.clone(),
                )
                .await;
            }

            transport::route(&websocket, &mut events, &mut request, &plan, &dns).await
        }
        .await
        {
            tracing::error!("channel task failed: {err:?}");
            drop(cleanup_websocket.close(Some(1011), Some("internal error")));
        }
    });

    Response::from_websocket(pair.client)
}
