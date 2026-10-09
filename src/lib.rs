#[cfg(not(any(feature = "dns", feature = "proxy")))]
compile_error!("enable at least one feature: dns or proxy");

mod config;
#[cfg(feature = "dns")]
mod dns;

#[cfg(feature = "dns")]
use crate::dns::DnsError;
#[cfg(feature = "dns")]
use crate::dns::util::read_body;
#[cfg(feature = "dns")]
use base64::Engine;
#[cfg(feature = "dns")]
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
#[cfg(feature = "proxy")]
mod proxy;
mod util;

use worker::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Route {
    #[cfg(feature = "dns")]
    Dns,
    #[cfg(feature = "proxy")]
    Proxy,
}

struct Routes {
    user_id: String,
    #[cfg(feature = "dns")]
    dns: String,
    #[cfg(feature = "proxy")]
    proxy: [String; 2],
}

impl Routes {
    fn route(&self, path: &str) -> Option<Route> {
        #[cfg(feature = "dns")]
        if self.dns == path {
            return Some(Route::Dns);
        }
        #[cfg(feature = "proxy")]
        if self.proxy.iter().any(|route| route == path) {
            return Some(Route::Proxy);
        }
        None
    }
}

#[allow(clippy::single_call_fn)]
fn routes(env: &Env) -> Result<&'static Routes> {
    static ROUTES: std::sync::OnceLock<std::result::Result<Routes, String>> =
        std::sync::OnceLock::new();
    ROUTES
        .get_or_init(|| {
            let user_id = env
                .var("UUID")
                .map_err(|_| "UUID is required".to_string())?
                .to_string();
            #[cfg(feature = "dns")]
            let dns = format!("/dns-query/{user_id}");
            #[cfg(feature = "proxy")]
            let proxy = [
                format!("/{user_id}"),
                format!("/{}", user_id.replace('-', "")),
            ];
            Ok(Routes {
                #[cfg(feature = "dns")]
                dns,
                #[cfg(feature = "proxy")]
                proxy,
                user_id,
            })
        })
        .as_ref()
        .map_err(|err| Error::RustError(err.clone()))
}

#[allow(clippy::single_call_fn)]
#[event(fetch)]
async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    static ACTA_GUARD: std::sync::OnceLock<Option<acta::TracingGuard>> = std::sync::OnceLock::new();
    let _ = ACTA_GUARD.get_or_init(|| {
        acta::init(
            acta::Config::builder()
                .with_writers([acta::Writer::stdout()
                    .with_format(acta::Format::Compact(acta::Formatter::new().with_style(
                        acta::Style {
                            icons: acta::Icons::NERD,
                            ..acta::Style::default()
                        },
                    )))
                    .with_color_depth(acta::ColorDepth::TrueColor)])
                .build(),
        )
        .ok()
    });

    let url = req.url()?;
    #[cfg(feature = "dns")]
    if url.path() == "/dns-query" || url.path().starts_with("/dns-query/") {
        let routes = routes(&env)?;
        if routes.route(url.path()) != Some(Route::Dns) {
            return error("Not Found", 404);
        }
        let config = config::Config::from_env(&env, &url, &routes.user_id)?;
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
        let client_ip = req
            .headers()
            .get("CF-Connecting-IP")?
            .and_then(|value| value.parse().ok());
        let prepared = match config.dns.prepare(&payload, client_ip) {
            Ok(prepared) => prepared,
            Err(DnsError::TooLarge) => return error("Invalid or oversized DNS query", 413),
            Err(_) => return error("Invalid or oversized DNS query", 400),
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
        };
    }

    #[cfg(feature = "proxy")]
    let websocket = req
        .headers()
        .get("Upgrade")
        .ok()
        .flatten()
        .is_some_and(|value| value.eq_ignore_ascii_case("websocket"));
    #[cfg(feature = "proxy")]
    if websocket {
        let routes = routes(&env)?;
        if routes.route(url.path()) != Some(Route::Proxy) {
            return Response::error("Not Found", 404);
        }
        tracing::info!("fetch: websocket upgrade requested");
        let config = config::Config::from_env(&env, &url, &routes.user_id)?;
        return proxy::handle(&env, &config, req, _ctx).await;
    }

    tracing::info!("fetch: request without websocket upgrade");
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
