mod config;
mod dns;
mod proxy;
mod util;

use std::sync::OnceLock;

use worker::*;

#[allow(clippy::single_call_fn)]
#[event(fetch)]
async fn fetch(req: Request, env: Env, ctx: Context) -> Result<Response> {
    static ACTA_GUARD: OnceLock<std::result::Result<acta::TracingGuard, String>> = OnceLock::new();
    if let Err(err) = ACTA_GUARD.get_or_init(|| {
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
        .map_err(|err| format!("Logging initialization failed: {err}"))
    }) {
        return Err(Error::RustError(err.clone()));
    }

    let url = req.url()?;
    tracing::info!("fetch: {} {}", req.method(), url.path());
    let config =
        config::Config::from_env(&env, &url.origin().ascii_serialization()).inspect_err(|err| {
            tracing::error!("Configuration failed: {err}");
        })?;
    if req
        .headers()
        .get("Upgrade")
        .ok()
        .flatten()
        .is_some_and(|value| value.eq_ignore_ascii_case("websocket"))
        && url.path() != dns::inbound::ws::PATH
    {
        tracing::info!("fetch: websocket upgrade requested");
        return proxy::handle(&config, req, ctx).await;
    }

    if url.path() == dns::inbound::https::PATH {
        return dns::inbound::https::handle(&config.dns, &config.dns.inbound.https, req).await;
    }
    if url.path() == dns::inbound::ws::PATH {
        return dns::inbound::ws::handle(&config.dns, &config.dns.inbound.ws, req, ctx);
    }

    tracing::info!("fetch: request without websocket upgrade");
    Response::from_json(&serde_json::json!({ "msg": "cfwp working!" }))
}
