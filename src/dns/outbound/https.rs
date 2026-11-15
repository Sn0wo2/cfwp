use wasm_bindgen::JsValue;
use worker::{AbortController, Error, Fetch, Headers, Method, Request, RequestInit, Result};

use crate::dns::{
    config::DnsServerConfig,
    transport,
    util::{is_dns_message_type, read_body},
    wire,
};

#[derive(Clone, Debug)]
pub(in crate::dns) struct Config {
    pub(in crate::dns) url: String,
}

impl Config {
    pub(in crate::dns) fn new(server: &DnsServerConfig) -> Result<Self> {
        let path = server.path.as_deref().unwrap_or("/dns-query");
        transport::validate_path(path)?;
        let url = transport::server_url(server, "https", 443, path)?;
        Ok(Self { url })
    }
}

pub(in crate::dns) async fn exchange(
    config: &Config,
    query: &[u8],
    max_message_bytes: usize,
) -> Result<Vec<u8>> {
    let headers = Headers::new();
    headers.set("accept", "application/dns-message")?;
    headers.set("content-type", "application/dns-message")?;

    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_redirect(worker::RequestRedirect::Manual)
        .with_headers(headers)
        .with_body(Some(JsValue::from(js_sys::Uint8Array::from(query))));

    let request = Request::new_with_init(&config.url, &init)?;
    let controller = AbortController::default();
    let signal = controller.signal();
    let mut abort_on_drop = AbortOnDrop(Some(controller));
    let mut response = Fetch::Request(request).send_with_signal(&signal).await?;
    let received_at = js_sys::Date::now();
    if response.status_code() != 200 {
        return Err(Error::RustError(format!(
            "DNS HTTPS upstream returned HTTP {}",
            response.status_code()
        )));
    }

    if !is_dns_message_type(
        &response
            .headers()
            .get("content-type")?
            .ok_or_else(|| Error::RustError("DNS HTTPS upstream omitted Content-Type".into()))?,
    ) {
        return Err(Error::RustError(
            "DNS HTTPS upstream returned an unexpected Content-Type".into(),
        ));
    }

    if let Some(length) = response
        .headers()
        .get("content-length")?
        .map(|length| {
            length.parse::<usize>().map_err(|_| {
                Error::RustError("DNS HTTPS upstream returned an invalid Content-Length".into())
            })
        })
        .transpose()?
        && length > max_message_bytes
    {
        return Err(Error::RustError(
            "DNS upstream response is too large".into(),
        ));
    }
    let age = match response.headers().get("age")? {
        Some(value) => value
            .parse::<u64>()
            .map(|age| age.min(u64::from(u32::MAX)) as u32)
            .map_err(|_| Error::RustError("DNS HTTPS upstream returned an invalid Age".into()))?,
        None => 0,
    };
    let mut bytes = read_body(response.stream()?, max_message_bytes).await?;
    wire::validate_response(query, &bytes)?;
    #[allow(clippy::cast_sign_loss)]
    let elapsed_seconds = ((js_sys::Date::now() - received_at) / 1000.0).max(0.0) as u32;
    wire::age(&mut bytes, age.saturating_add(elapsed_seconds))?;
    abort_on_drop.0.take();
    Ok(bytes)
}

struct AbortOnDrop(Option<AbortController>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        if let Some(controller) = self.0.take() {
            controller.abort();
        }
    }
}
