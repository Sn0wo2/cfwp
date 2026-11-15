#![allow(clippy::single_call_fn)]

use std::net::IpAddr;

use futures_util::StreamExt;
use worker::{Context, Error, Headers, Request, Response, Result, WebSocketPair, WebsocketEvent};

use dns_over_websocket::{Incoming, Server, Status};

use crate::dns::{DnsError, DnsService, config::DnsConfig};

pub(crate) const PATH: &str = dns_over_websocket::PATH;
const MAX_PENDING: usize = 64;

#[derive(Clone)]
pub(crate) struct Config {
    pub(crate) max_message_bytes: usize,
}

impl Config {
    pub(crate) const fn new(config: &DnsConfig) -> Self {
        Self {
            max_message_bytes: config.max_message_bytes,
        }
    }
}

pub(crate) fn handle(
    dns: &DnsService,
    config: &Config,
    req: Request,
    ctx: Context,
) -> Result<Response> {
    if !req
        .headers()
        .get("upgrade")?
        .is_some_and(|value| value.eq_ignore_ascii_case("websocket"))
    {
        let mut response = Response::error("WebSocket upgrade required", 426)?;
        response.headers_mut().set("upgrade", "websocket")?;
        return Ok(response);
    }

    let url = req.url()?;
    let protocol = req.headers().get("sec-websocket-protocol")?;
    let request_headers = protocol
        .as_deref()
        .map_or_else(Vec::new, |value| vec![("sec-websocket-protocol", value)]);
    let handshake = dns_over_websocket::handshake::Request {
        path: url.path(),
        query: url.query(),
        headers: &request_headers,
    };
    if let Err(err) = dns_over_websocket::handshake::validate_server_request(
        &dns_over_websocket::handshake::Auth::default(),
        &handshake,
    ) {
        return Response::error("Invalid DNS WebSocket handshake", err.status_code());
    }

    let pair = WebSocketPair::new()?;
    pair.server.accept()?;
    let websocket = pair.server;
    let dns = dns.clone();
    let config = config.clone();
    let client_ip = req
        .headers()
        .get("CF-Connecting-IP")?
        .and_then(|value| value.parse::<IpAddr>().ok());
    ctx.wait_until(async move {
        let cleanup_websocket = websocket.clone();
        let result: Result<()> = async move {
            let mut events = websocket.events()?;
            let mut server = Server::new(MAX_PENDING, config.max_message_bytes)
                .map_err(|err| Error::RustError(err.to_string()))?;
            while let Some(event) = events.next().await {
                match event? {
                    WebsocketEvent::Message(message) => {
                        let Some(text) = message.text() else {
                            websocket.close(Some(1003), Some("text messages required"))?;
                            return Ok(());
                        };
                        let incoming = match server.receive(&text) {
                            Ok(incoming) => incoming,
                            Err(err) => {
                                tracing::warn!("DNS WebSocket protocol error: {err}");
                                websocket.close(Some(1008), Some("invalid protocol message"))?;
                                return Ok(());
                            }
                        };
                        let text = match incoming {
                            Incoming::Reply(response) => response
                                .to_text()
                                .map_err(|err| Error::RustError(err.to_string()))?,
                            Incoming::Query(query) => {
                                let response = query
                                    .resolve(|payload| {
                                        let dns = dns.clone();
                                        async move {
                                            match dns.exchange(&payload, client_ip).await {
                                                Ok(response) => Ok(response),
                                                Err(DnsError::Timeout(_)) => Err(Status::Timeout),
                                                Err(_) => Err(Status::UpstreamFailure),
                                            }
                                        }
                                    })
                                    .await;
                                server
                                    .finish(&response)
                                    .map_err(|err| Error::RustError(err.to_string()))?
                            }
                        };
                        websocket.send_with_str(text)?;
                    }
                    WebsocketEvent::Close(_) => return Ok(()),
                }
            }
            Ok(())
        }
        .await;
        if let Err(err) = result {
            tracing::error!("DNS WebSocket session failed: {err:?}");
            drop(cleanup_websocket.close(Some(1011), Some("internal error")));
        }
    });

    let headers = Headers::new();
    headers.set("sec-websocket-protocol", dns_over_websocket::SUBPROTOCOL)?;
    Ok(Response::from_websocket(pair.client)?.with_headers(headers))
}
