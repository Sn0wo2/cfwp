use std::cell::Cell;
use std::net::IpAddr;
use std::rc::Rc;

use base64::Engine;
use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
use futures_util::StreamExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt, split};
use worker::{
    Context, Env, Request, Response, Result, Socket, WebSocket, WebSocketPair, WebsocketEvent,
};

use super::outbound::ProxyPlan;
use super::protocol::{Codec, InitialRequest};
use super::util::{CONNECT_TIMEOUT_MS, connect_tcp};
use crate::util::with_timeout;

#[allow(clippy::single_call_fn)]
pub(crate) async fn handle(
    env: &Env,
    config: &crate::config::Config,
    req: Request,
    ctx: Context,
) -> Result<Response> {
    let request_url = req.url()?;
    let user_id = config.user_id.clone();
    if request_url.path().strip_prefix('/') != Some(user_id.as_str())
        && request_url.path().strip_prefix('/') != Some(user_id.replace('-', "").as_str())
    {
        acta::error!("fetch: websocket path mismatch");
        return Response::error("Not Found", 404);
    }

    let mut plan = ProxyPlan {
        entries: ProxyPlan::collect_entries(
            env.var("PROXYIP").ok().map(|value| value.to_string()),
            env.var("PROXY").ok().map(|value| value.to_string()),
            false,
        )?,
    };
    plan.entries.extend(ProxyPlan::collect_entries(
        request_url
            .query_pairs()
            .find(|(key, _)| key.eq_ignore_ascii_case("proxyip"))
            .map(|(_, value)| value.into_owned()),
        request_url
            .query_pairs()
            .find(|(key, _)| key.eq_ignore_ascii_case("proxy"))
            .map(|(_, value)| value.into_owned()),
        true,
    )?);
    let early_data = req
        .headers()
        .get("sec-websocket-protocol")
        .ok()
        .flatten()
        .unwrap_or_default();
    #[cfg(feature = "dns")]
    let client_ip = req
        .headers()
        .get("CF-Connecting-IP")
        .ok()
        .flatten()
        .and_then(|value| value.parse::<IpAddr>().ok());
    #[cfg(feature = "dns")]
    let dns = Some(Rc::new(config.dns.clone()));

    let pair = WebSocketPair::new()?;
    pair.server
        .as_ref()
        .set_binary_type(web_sys::BinaryType::Arraybuffer);
    pair.server.accept()?;
    let websocket = pair.server;

    ctx.wait_until(async move {
        acta::info!("session: websocket accepted");
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
                        acta::error!("session: ignoring invalid early data: {err}");
                        Vec::new()
                    })
            };
            if !initial.is_empty() {
                acta::info!("session: early data received ({} bytes)", initial.len());
            }
            while initial.is_empty() {
                match events.next().await {
                    Some(event) => match event? {
                        WebsocketEvent::Message(message) => {
                            if let Some(payload) = decode_message(message) {
                                acta::info!(
                                    "session: first websocket message ({} bytes)",
                                    payload.len()
                                );
                                initial = payload;
                            }
                        }
                        WebsocketEvent::Close(_) => {
                            acta::info!("session: websocket closed before first message");
                            break;
                        }
                    },
                    None => break,
                }
            }
            if initial.is_empty() {
                acta::info!("session: closed without an initial payload");
                websocket.close(None, None::<String>)?;
                return Ok(());
            }

            const MAX_INITIAL_HEADER: usize = 64 * 1024;
            acta::info!("session: parsing initial payload ({} bytes)", initial.len());
            let mut trailing = if initial.len() > MAX_INITIAL_HEADER {
                initial.split_off(MAX_INITIAL_HEADER)
            } else {
                Vec::new()
            };
            let mut request = match loop {
                match InitialRequest::parse(&initial, &user_id).await {
                    Ok(Some(mut request)) => {
                        if !trailing.is_empty() {
                            let decoded = request.codec.inbound.decode(&trailing).await?;
                            request.payload.extend_from_slice(&decoded);
                        }
                        break Ok(request);
                    }
                    Ok(None) if initial.len() < MAX_INITIAL_HEADER => match events.next().await {
                        Some(Ok(WebsocketEvent::Message(message))) => {
                            if let Some(bytes) = decode_message(message) {
                                acta::info!("session: continued header ({} bytes)", bytes.len());
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
                    acta::error!("session: request parse failed: {err:?}");
                    drop(websocket.close(Some(1008), Some("invalid request")));
                    return Err(err);
                }
            };
            acta::info!("session: request parsed (port={})", request.port);

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
                acta::error!("session: invalid target authority");
                drop(websocket.close(Some(1008), Some("invalid request")));
                return Err(worker::Error::RustError("invalid target authority".into()));
            }

            if request.hostname == "speed.cloudflare.com"
                || request.hostname.ends_with(".speed.cloudflare.com")
            {
                websocket.close(Some(1008), Some("blocked"))?;
                return Ok(());
            }

            #[cfg(feature = "dns")]
            let udp_only = request.is_udp && !request.is_dns_request();
            #[cfg(not(feature = "dns"))]
            let udp_only = request.is_udp;
            if udp_only {
                acta::info!("session: UDP request unsupported");
                websocket.close(Some(1003), Some("udp unsupported"))?;
                return Ok(());
            }

            #[cfg(feature = "dns")]
            if request.is_dns_request() {
                acta::info!("session: forwarding DNS request");
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
                        let response = match dns.as_ref() {
                            Some(dns) => {
                                dns.exchange_prepared(dns.prepare(query, client_ip)?)
                                    .await?
                            }
                            None => return Ok(()),
                        };
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
                            if let Some(bytes) = decode_message(message) {
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
                acta::info!("session: mux session accepted ({mode:?})");
                let InitialRequest { payload, codec, .. } = request;
                return super::mux::handle(&websocket, events, codec, payload, mode).await;
            }

            acta::info!("session: connecting primary target (port={})", request.port);
            #[cfg(feature = "dns")]
            let hostname = match dns.as_deref() {
                Some(dns) => {
                    use domain::base::{Message, MessageBuilder, Name, Rtype};
                    use domain::rdata::AllRecordData;

                    let resolved: Result<Option<IpAddr>> = async {
                        if request.hostname.parse::<IpAddr>().is_ok() {
                            return Ok(None);
                        }
                        let Ok(name) = Name::vec_from_str(&request.hostname) else {
                            return Ok(None);
                        };
                        let mut id = [0_u8; 2];
                        getrandom::fill(&mut id)
                            .map_err(|_| worker::Error::RustError("rng failed".into()))?;
                        let mut builder = MessageBuilder::new_vec();
                        builder.header_mut().set_id(u16::from_be_bytes(id));
                        builder.header_mut().set_rd(true);
                        let mut question = builder.question();
                        question.push((name, Rtype::A)).map_err(|_| {
                            worker::Error::RustError("invalid DNS query name".into())
                        })?;
                        let query = question.into_message().into_octets();

                        let response = dns.exchange(&query, None).await.map_err(|err| {
                            worker::Error::RustError(format!("DNS resolution failed: {err}"))
                        })?;
                        let Ok(message) = Message::from_octets(&response) else {
                            return Ok(None);
                        };
                        if message.header().rcode() != domain::base::iana::Rcode::NOERROR {
                            return Ok(None);
                        }
                        let Ok(answer) = message.answer() else {
                            return Ok(None);
                        };
                        for parsed in answer.flatten() {
                            if parsed.rtype() != Rtype::A && parsed.rtype() != Rtype::AAAA {
                                continue;
                            }
                            let Ok(Some(record)) = parsed.into_record::<
                                AllRecordData<
                                    &[u8],
                                    domain::base::name::ParsedName<&[u8]>,
                                >,
                            >() else {
                                continue;
                            };
                            return Ok(match record.data() {
                                AllRecordData::A(a) => Some(IpAddr::V4(a.addr())),
                                AllRecordData::Aaaa(a) => Some(IpAddr::V6(a.addr())),
                                _ => None,
                            });
                        }
                        Ok(None)
                    }
                    .await;
                    match resolved {
                        Ok(Some(ip)) => ip.to_string(),
                        Ok(None) => request.hostname.clone(),
                        Err(err) => {
                            acta::warn!("session: DNS resolution failed, using hostname: {err}");
                            request.hostname.clone()
                        }
                    }
                }
                None => request.hostname.clone(),
            };
            #[cfg(not(feature = "dns"))]
            let hostname = request.hostname.clone();
            match match connect_tcp(&hostname, request.port) {
                Err(err) => Err(err),
                Ok(mut socket) => match with_timeout(CONNECT_TIMEOUT_MS, async {
                    socket.opened().await?;
                    if !request.payload.is_empty() {
                        socket.write_all(&request.payload).await?;
                        socket.flush().await?;
                    }
                    Ok(())
                })
                .await
                {
                    Some(Ok(())) => Ok(socket),
                    Some(Err(err)) => {
                        drop(socket.close().await);
                        Err(err)
                    }
                    None => {
                        drop(socket.close().await);
                        Err(worker::Error::RustError(format!(
                            "target connection timed out after {CONNECT_TIMEOUT_MS} ms"
                        )))
                    }
                },
            } {
                Ok(mut socket) => {
                    acta::info!("session: primary connection opened");
                    let (has_data, has_client_data) = match pipe_streams(
                        &websocket,
                        &mut events,
                        &mut socket,
                        &mut request.codec,
                    )
                    .await
                    {
                        Ok(result) => result,
                        Err(err) => {
                            drop(socket.close().await);
                            return Err(err);
                        }
                    };
                    drop(socket.close().await);
                    acta::info!("session: primary stream ended (remote_data={has_data})");
                    if has_data || has_client_data || !plan.has_entries() {
                        websocket.close(None, None::<String>)?;
                        return Ok(());
                    }
                    acta::info!("session: trying alternate route after empty response");
                    let mut fallback = plan.connect_via_entries(&request).await?;
                    if let Err(err) =
                        pipe_streams(&websocket, &mut events, &mut fallback, &mut request.codec)
                            .await
                    {
                        drop(fallback.close().await);
                        return Err(err);
                    }
                    drop(fallback.close().await);
                    websocket.close(None, None::<String>)?;
                    Ok(())
                }
                Err(err) => {
                    acta::error!("session: primary connection failed: {err:?}");
                    if !plan.has_entries() {
                        return Err(err);
                    }
                    acta::info!("session: trying alternate route");
                    let mut fallback = plan.connect_via_entries(&request).await?;
                    if let Err(err) =
                        pipe_streams(&websocket, &mut events, &mut fallback, &mut request.codec)
                            .await
                    {
                        drop(fallback.close().await);
                        return Err(err);
                    }
                    drop(fallback.close().await);
                    websocket.close(None, None::<String>)?;
                    Ok(())
                }
            }
        }
        .await
        {
            acta::error!("channel task failed: {err:?}");
            drop(cleanup_websocket.close(Some(1011), Some("internal error")));
        }
    });

    Response::from_websocket(pair.client)
}

async fn pipe_streams(
    websocket: &WebSocket,
    events: &mut worker::EventStream<'_>,
    socket: &mut Socket,
    codec: &mut Codec,
) -> Result<(bool, bool)> {
    let (mut reader_socket, mut writer_socket) = split(socket);
    let (decoder, encoder) = (&mut codec.inbound, &mut codec.outbound);
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
                .ok_or_else(|| worker::Error::RustError("invalid socket read length".into()))?;
            websocket.send_with_bytes(encoder.encode(bytes).await?)?;
        }
        Ok::<bool, worker::Error>(has_data)
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
        Ok::<(), worker::Error>(())
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

fn decode_message(message: worker::MessageEvent) -> Option<Vec<u8>> {
    message
        .bytes()
        .filter(|bytes| !bytes.is_empty())
        .or_else(|| {
            message
                .text()
                .and_then(|text| (!text.is_empty()).then_some(text.into_bytes()))
        })
}
