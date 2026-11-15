#![allow(clippy::single_call_fn)]

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use worker::{Headers, Method, Request, Response, Result};

use crate::dns::{
    DnsError, DnsService,
    config::DnsConfig,
    util::{DNS_MESSAGE_TYPE, is_dns_message_type, read_body},
};
use crate::util::error;

pub(crate) const PATH: &str = "/dns-query";

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

pub(crate) async fn handle(
    dns: &DnsService,
    config: &Config,
    mut req: Request,
) -> Result<Response> {
    let limit = config.max_message_bytes;
    let payload = match req.method() {
        Method::Get => {
            let url = req.url()?;
            let mut params = url.query_pairs().filter(|(name, _)| name == "dns");
            let Some((_, dns)) = params.next() else {
                return error("Missing dns parameter", 400);
            };
            if params.next().is_some() {
                return error("Duplicate dns parameter", 400);
            }
            if dns.len() > limit.div_ceil(3) * 4 {
                return error("DNS query too large", 413);
            }
            match URL_SAFE_NO_PAD.decode(dns.as_bytes()) {
                Ok(bytes) if bytes.len() <= limit => bytes,
                Ok(_) => return error("DNS query too large", 413),
                Err(_) => return error("Invalid base64url DNS query", 400),
            }
        }
        Method::Post => {
            if !is_dns_message_type(&req.headers().get("content-type")?.unwrap_or_default()) {
                return error("Expected application/dns-message", 415);
            }
            if let Some(length) = req.headers().get("content-length")? {
                match length.parse::<usize>() {
                    Ok(length) if length <= limit => {}
                    Ok(_) => return error("DNS query too large", 413),
                    Err(_) => return error("Invalid Content-Length", 400),
                }
            }
            match read_body(req.stream()?, limit).await {
                Ok(bytes) => bytes,
                Err(DnsError::TooLarge) => return error("Invalid or oversized DNS body", 413),
                Err(_) => return error("Invalid or oversized DNS body", 400),
            }
        }
        _ => {
            let mut response = error("Method Not Allowed", 405)?;
            response.headers_mut().set("allow", "GET, POST")?;
            return Ok(response);
        }
    };

    let prepared = match dns.prepare(
        &payload,
        req.headers()
            .get("CF-Connecting-IP")?
            .and_then(|value| value.parse().ok()),
    ) {
        Ok(prepared) => prepared,
        Err(DnsError::TooLarge) => return error("Invalid or oversized DNS query", 413),
        Err(_) => return error("Invalid or oversized DNS query", 400),
    };
    match dns.exchange_prepared(prepared).await {
        Ok(bytes) => {
            let headers = Headers::new();
            headers.set("content-type", DNS_MESSAGE_TYPE)?;
            headers.set("cache-control", "no-store")?;
            headers.set("x-content-type-options", "nosniff")?;
            Ok(Response::from_bytes(bytes)?.with_headers(headers))
        }
        Err(err) => {
            tracing::error!("DNS exchange failed: {err}");
            error(
                "DNS upstream unavailable",
                if matches!(err, DnsError::Timeout(_)) {
                    504
                } else {
                    502
                },
            )
        }
    }
}
