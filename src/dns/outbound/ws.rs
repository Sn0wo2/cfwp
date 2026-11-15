use futures_util::StreamExt;
use worker::{Error, Result, Url, WebSocket, WebsocketEvent};

use dns_over_websocket::{Client, PATH, Query, Response, SUBPROTOCOL};

use crate::dns::{
    config::{DnsServerConfig, DnsServerType},
    transport, wire,
};

#[derive(Clone, Debug)]
pub(in crate::dns) struct Config {
    pub(in crate::dns) url: String,
}

impl Config {
    pub(in crate::dns) fn new(server: &DnsServerConfig) -> Result<Self> {
        let (scheme, default_port) = match server.kind {
            DnsServerType::Ws => ("ws", 80),
            DnsServerType::Wss => ("wss", 443),
            _ => {
                return Err(Error::RustError(
                    "invalid DNS config: WebSocket transport expected".into(),
                ));
            }
        };
        let path = server.path.as_deref().unwrap_or(PATH);
        transport::validate_path(path)?;
        let url = transport::server_url(server, scheme, default_port, path)?;
        Ok(Self { url })
    }
}

pub(in crate::dns) async fn exchange(
    config: &Config,
    query: &[u8],
    max_message_bytes: usize,
) -> Result<Vec<u8>> {
    let websocket =
        WebSocket::connect_with_protocols(Url::parse(&config.url)?, Some(vec![SUBPROTOCOL]))
            .await?;
    let _close_on_drop = CloseOnDrop(websocket.clone());
    let mut events = websocket.events()?;
    websocket.accept()?;

    let mut client = Client::new(1);
    let request = Query {
        id: 0,
        dns: query.to_vec(),
    };
    websocket.send_with_str(
        client
            .send(&request)
            .map_err(|err| Error::RustError(err.to_string()))?,
    )?;

    let response = match events.next().await {
        Some(Ok(WebsocketEvent::Message(message))) => {
            let Some(text) = message.text() else {
                return Err(Error::RustError(
                    "DNS WebSocket upstream returned a non-text message".into(),
                ));
            };
            client
                .receive(&text)
                .map_err(|err| Error::RustError(err.to_string()))?
        }
        Some(Ok(WebsocketEvent::Close(_))) | None => {
            return Err(Error::RustError(
                "DNS WebSocket upstream closed before responding".into(),
            ));
        }
        Some(Err(err)) => return Err(err),
    };
    let bytes = match response {
        Response::Success { dns, .. } => dns,
        Response::Failure { status, .. } => {
            return Err(Error::RustError(format!(
                "DNS WebSocket upstream returned {status:?}"
            )));
        }
    };
    if bytes.len() > max_message_bytes {
        return Err(Error::RustError(
            "DNS upstream response is too large".into(),
        ));
    }
    wire::validate_response(query, &bytes)?;
    Ok(bytes)
}

struct CloseOnDrop(WebSocket);

impl Drop for CloseOnDrop {
    fn drop(&mut self) {
        drop(self.0.close(None, None::<String>));
    }
}
