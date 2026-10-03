#[cfg(not(any(feature = "dns", feature = "proxy")))]
compile_error!("enable at least one feature: dns or proxy");

mod config;
#[cfg(feature = "dns")]
mod dns;

#[cfg(feature = "dns")]
use crate::dns::util::read_body;
#[cfg(feature = "dns")]
use base64::Engine;
#[cfg(feature = "dns")]
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
#[cfg(feature = "proxy")]
mod proxy;

use worker::*;

#[allow(clippy::single_call_fn)]
#[event(fetch)]
async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    let _acta_guard = acta::init(
        acta::Writer::stdout()
            .with_style(acta::Style {
                icons: acta::Icons::NERD,
                ..acta::Style::default()
            })
            .with_color_depth(acta::ColorDepth::TrueColor),
    );

    let url = req.url()?;
    #[cfg(feature = "dns")]
    if url.path() == "/dns-query" || url.path().starts_with("/dns-query/") {
        let config = config::Config::from_env(&env, &url)?;
        let mut req = req;
        let limit = config.dns.config.max_message_bytes;
        let payload = match req.method() {
            Method::Get => {
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
                let content_type = req.headers().get("content-type")?.unwrap_or_default();
                if !content_type.split(';').next().is_some_and(|value| {
                    value.trim().eq_ignore_ascii_case("application/dns-message")
                }) {
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
                    Err(err) => {
                        return error(
                            "Invalid or oversized DNS body",
                            if err.to_string().contains("too large") {
                                413
                            } else {
                                400
                            },
                        );
                    }
                }
            }
            _ => {
                let mut response = error("Method Not Allowed", 405)?;
                response.headers_mut().set("allow", "GET, POST")?;
                return Ok(response);
            }
        };
        let client_ip = req
            .headers()
            .get("CF-Connecting-IP")?
            .and_then(|value| value.parse().ok());
        let prepared = match config.dns.prepare(&payload, client_ip) {
            Ok(prepared) => prepared,
            Err(err) => {
                return error(
                    "Invalid or oversized DNS query",
                    if err.to_string().contains("too large") {
                        413
                    } else {
                        400
                    },
                );
            }
        };
        return match config.dns.exchange_prepared(prepared).await {
            Ok(bytes) => {
                let headers = Headers::new();
                headers.set("content-type", "application/dns-message")?;
                headers.set("cache-control", "no-store")?;
                headers.set("x-content-type-options", "nosniff")?;
                Ok(Response::from_bytes(bytes)?.with_headers(headers))
            }
            Err(err) => {
                acta::error!("DNS exchange failed: {err}");
                error(
                    "DNS upstream unavailable",
                    if err.to_string().contains("timed out") {
                        504
                    } else {
                        502
                    },
                )
            }
        };
    }

    #[cfg(feature = "proxy")]
    if req
        .headers()
        .get("Upgrade")
        .ok()
        .flatten()
        .is_some_and(|value| value.eq_ignore_ascii_case("websocket"))
    {
        acta::info!("fetch: websocket upgrade requested");
        let config = config::Config::from_env(&env, &url)?;
        return proxy::handle(&env, &config, req, _ctx).await;
    }

    acta::info!("fetch: request without websocket upgrade");
    Response::from_json(&std::collections::BTreeMap::from([(
        "msg",
        "cfwp working!",
    )]))
}

#[cfg(feature = "dns")]
fn error(message: &str, status: u16) -> Result<Response> {
    let mut response = Response::error(message, status)?;
    response.headers_mut().set("cache-control", "no-store")?;
    response
        .headers_mut()
        .set("x-content-type-options", "nosniff")?;
    Ok(response)
}
