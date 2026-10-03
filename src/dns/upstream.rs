use std::{cell::RefCell, future::Future, rc::Rc, time::Duration};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use domain::base::iana::OptRcode;
use futures_util::{FutureExt, StreamExt, future::select, stream::FuturesUnordered};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use worker::{
    AbortController, Delay, Env, Error, Fetch, Headers, Method, Request, RequestInit, Result,
    Socket, Url,
};

use crate::wasm_bindgen::JsValue;

use super::{
    DnsService,
    cache::DnsCache,
    config::{self, DnsConfig, Strategy},
    util::read_body,
    wire,
};

#[derive(Clone)]
pub(super) struct UpstreamPool {
    upstreams: Rc<[CompiledUpstream]>,
    strategy: Strategy,
    timeout_ms: u32,
    request_timeout_ms: u32,
    race_concurrency: usize,
    probe: Option<Rc<[u16]>>,
    max_message_bytes: usize,
    probe_order_cache: Rc<RefCell<Option<Rc<[usize]>>>>,
}

pub(super) struct UpstreamResponse {
    pub(super) bytes: Vec<u8>,
    pub(super) retried_without_ecs: bool,
}

#[derive(Clone, Debug)]
struct CompiledUpstream {
    transport: Transport,
    timeout_ms: Option<u32>,
}

#[derive(Clone, Debug)]
enum Transport {
    Https { url: String },
    Tls { host: String, port: u16 },
    Tcp { host: String, port: u16 },
}

impl DnsService {
    #[allow(clippy::single_call_fn)]
    pub(crate) fn new(env: &Env, origin: &str, user_id: &str) -> Result<Self> {
        let config: DnsConfig = match env.var("DNS").ok() {
            Some(value) => serde_json::from_str(&value.to_string())
                .map_err(|err| Error::RustError(format!("DNS is invalid: {err}")))?,
            None => DnsConfig::default(),
        };

        if config.upstreams.is_empty() {
            return Err(config::config_error(
                "upstreams must contain at least one URL",
            ));
        }
        if config.upstreams.len() > config::MAX_UPSTREAMS {
            return Err(config::config_error(
                "upstreams may contain at most 16 URLs",
            ));
        }
        for upstream in &config.upstreams {
            if upstream.url().trim().is_empty() {
                return Err(config::config_error("upstream URLs must not be empty"));
            }
            if let Some(timeout_ms) = upstream.timeout_ms() {
                config::validate_timeout("upstream timeout_ms", timeout_ms)?;
            }
        }
        config::validate_timeout("timeout_ms", config.timeout_ms)?;
        config::validate_timeout("request_timeout_ms", config.request_timeout_ms)?;
        if !(1..=6).contains(&config.race_concurrency) {
            return Err(config::config_error(
                "race_concurrency must be between 1 and 6",
            ));
        }
        config::validate_message_size("max_message_bytes", config.max_message_bytes)?;

        if let Some(ecs) = &config.ecs {
            if ecs.ipv4_prefix > 32 {
                return Err(config::config_error("ecs.ipv4_prefix must not exceed 32"));
            }
            if ecs.ipv6_prefix > 128 {
                return Err(config::config_error("ecs.ipv6_prefix must not exceed 128"));
            }
        }

        if let Some(cache) = &config.cache {
            if !(1..=86_400).contains(&cache.max_ttl) {
                return Err(config::config_error(
                    "cache.max_ttl must be between 1 and 86400",
                ));
            }
            config::validate_message_size("cache.max_message_bytes", cache.max_message_bytes)?;
        }

        Ok(Self {
            upstreams: UpstreamPool {
            upstreams: Rc::from(
                    config
                        .upstreams
                        .iter()
                        .map(|config| {
                            let value = config.url().trim();
                            let url = Url::parse(value).map_err(|err| {
                                Error::RustError(format!("invalid DNS upstream URL: {err}"))
                            })?;

                            if !url.username().is_empty()
                                || url.password().is_some()
                                || value.split_once("://").is_some_and(|(_, rest)| {
                                    rest.split(['/', '?', '#'])
                                        .next()
                                        .unwrap_or(rest)
                                        .contains('@')
                                })
                            {
                                return Err(Error::RustError(
                                    "DNS upstream URL credentials are not allowed".into(),
                                ));
                            }
                            if url.fragment().is_some() {
                                return Err(Error::RustError(
                                    "DNS upstream URL fragments are not allowed".into(),
                                ));
                            }
                            if url.port() == Some(0) {
                                return Err(Error::RustError(
                                    "DNS upstream URL port must not be zero".into(),
                                ));
                            }

                            Ok(CompiledUpstream {
                                transport: match url.scheme() {
                                    "https" => {
                                        if url.host_str().is_none() {
                                            return Err(Error::RustError(
                                                "DNS HTTPS upstream requires a host".into(),
                                            ));
                                        }
                                        Transport::Https {
                                            url: url.to_string(),
                                        }
                                    }
                                    "tls" | "tcp" => {
                                        if !matches!(url.path(), "" | "/")
                                            || url.query().is_some()
                                        {
                                            return Err(Error::RustError(
                                                "DNS TCP/TLS upstreams must not specify a path or query"
                                                    .into(),
                                            ));
                                        }
                                        let parsed_host = url.host_str().ok_or_else(|| {
                                            Error::RustError("DNS upstream requires a host".into())
                                        })?;
                                        let host = parsed_host
                                            .strip_prefix('[')
                                            .and_then(|host| host.strip_suffix(']'))
                                            .unwrap_or(parsed_host)
                                            .to_string();
                                        let (tls, default_port) = if url.scheme() == "tls" {
                                            (true, 853)
                                        } else {
                                            (false, 53)
                                        };
                                        let port = url.port().unwrap_or(default_port);
                                        if tls {
                                            Transport::Tls { host, port }
                                        } else {
                                            Transport::Tcp { host, port }
                                        }
                                    }
                                    _ => {
                                        return Err(Error::RustError(
                                            "DNS upstream scheme must be https, tls, or tcp".into(),
                                        ));
                                    }
                                },
                                timeout_ms: config.timeout_ms(),
                            })
                        })
                        .collect::<Result<Vec<_>>>()?,
                ),
                strategy: config.strategy,
                timeout_ms: config.timeout_ms,
                request_timeout_ms: config.request_timeout_ms,
                race_concurrency: config.race_concurrency,
                probe: Some(Rc::from(config.probe.as_deref().map_or_else(
                    Vec::new,
                    |value| {
                        value
                        .split([',', '\n'])
                        .filter_map(|entry| {
                            let entry = entry.trim();
                            let (scheme, port) = entry.split_once(':')?;
                            if scheme != "tcp" {
                                return None;
                            }
                            let port = port.parse::<u16>().ok()?;
                            (port != 0).then_some(port)
                        })
                        .collect()
                    },
                ))),
                max_message_bytes: config.max_message_bytes,
                probe_order_cache: Rc::new(RefCell::new(None)),
            },
            cache: config
                .cache
                .as_ref()
                    .map(|cache_config| -> Result<Rc<DnsCache>> {
                    let mut hash = Sha256::new();
                    hash.update(b"cfwp-dns-v1\0");
                    hash.update(user_id.as_bytes());
                    hash.update(serde_json::to_vec(&config)?);
                    Ok(Rc::new(DnsCache {
                        prefix: format!(
                            "{origin}/.cfwp/dns/{}/",
                            URL_SAFE_NO_PAD.encode(hash.finalize())
                        ),
                            config: cache_config.clone(),
                    }))
                })
                .transpose()?,
            config: Rc::new(config),
        })
    }
}

impl UpstreamPool {
    pub(super) async fn exchange(
        &self,
        query: &[u8],
        retry_without_ecs: Option<&[u8]>,
    ) -> Result<UpstreamResponse> {
        if query.len() < 12 {
            return Err(Error::RustError(
                "DNS query is shorter than its header".into(),
            ));
        }
        if query.len() > self.max_message_bytes {
            return Err(Error::RustError("DNS query is too large".into()));
        }

        let operation = async {
            match self.strategy {
                Strategy::None => self.exchange_in_order(query, retry_without_ecs, 0).await,
                Strategy::FastestV4 | Strategy::FastestV6 | Strategy::FastestAll => {
                    let start = if self.probe.is_none() {
                        0
                    } else if let Some(order) = self.probe_order_cache.borrow().as_ref()
                        && let Some(&first) = order.first()
                    {
                        first
                    } else {
                        let probes = self.probe.as_deref().ok_or_else(|| {
                            Error::RustError("DNS probe configuration is unavailable".into())
                        })?;
                        let mut latencies: Vec<(usize, Option<u32>)> = Vec::new();
                        for (index, upstream) in self.upstreams.iter().enumerate() {
                            let target = match &upstream.transport {
                                Transport::Https { url } => Url::parse(url).ok().and_then(|url| {
                                    Some((
                                        url.host_str()?.to_string(),
                                        url.port().unwrap_or(443),
                                        true,
                                    ))
                                }),
                                Transport::Tls { host, port } => Some((host.clone(), *port, true)),
                                Transport::Tcp { host, port } => Some((host.clone(), *port, false)),
                            };
                            let Some((host, ..)) = target else {
                                latencies.push((index, None));
                                continue;
                            };
                            if probes.is_empty() {
                                latencies.push((index, None));
                                continue;
                            }
                            let mut latency = None;
                            for port in probes {
                                let ms = async {
                                    let started = js_sys::Date::now();
                                    let socket =
                                        Socket::builder().connect(host.to_string(), *port).ok()?;
                                    let mut socket = SocketOnDrop(Some(socket));
                                    if let Some(socket) = socket.0.as_mut() {
                                        socket.opened().await.ok()?;
                                    }
                                    #[allow(clippy::cast_sign_loss)]
                                    let elapsed = (js_sys::Date::now() - started)
                                        .min(f64::from(u32::MAX))
                                        as u32;
                                    drop(socket);
                                    Some(elapsed)
                                }
                                .await;
                                if let Some(ms) = ms {
                                    acta::info!("DNS probe {host}:{port} -> {ms} ms");
                                    latency = Some(ms);
                                    break;
                                }
                            }
                            latencies.push((index, latency));
                        }
                        latencies
                            .sort_by_key(|(index, latency)| (latency.unwrap_or(u32::MAX), *index));
                        let order: Vec<usize> =
                            latencies.into_iter().map(|(index, _)| index).collect();
                        let first = order.first().copied().unwrap_or(0);
                        *self.probe_order_cache.borrow_mut() = Some(Rc::from(order));
                        first
                    };
                    self.exchange_in_order(query, retry_without_ecs, start)
                        .await
                }
                Strategy::First => {
                    let mut pending = FuturesUnordered::new();
                    let mut next_upstream = 0;
                    let mut last_error = None;
                    let mut last_dns_error = None;

                    while next_upstream < self.upstreams.len()
                        && pending.len() < self.race_concurrency
                    {
                        pending.push(self.exchange_one(next_upstream, query, retry_without_ecs));
                        next_upstream += 1;
                    }

                    while let Some(result) = pending.next().await {
                        match result {
                            Ok(response) if wire::response_is_success(&response.bytes)? => {
                                return Ok(response);
                            }
                            Ok(response) => last_dns_error = Some(response),
                            Err(err) => last_error = Some(err),
                        }
                        if next_upstream < self.upstreams.len() {
                            pending.push(self.exchange_one(
                                next_upstream,
                                query,
                                retry_without_ecs,
                            ));
                            next_upstream += 1;
                        }
                    }

                    last_dns_error.map_or_else(
                        || {
                            Err(last_error.unwrap_or_else(|| {
                                Error::RustError("no DNS upstream available".into())
                            }))
                        },
                        Ok,
                    )
                }
            }
        };
        with_timeout(self.request_timeout_ms, operation)
            .await
            .unwrap_or_else(|| Err(timeout_error("DNS request", self.request_timeout_ms)))
    }

    async fn exchange_in_order(
        &self,
        query: &[u8],
        retry_without_ecs: Option<&[u8]>,
        start: usize,
    ) -> Result<UpstreamResponse> {
        let mut last_error = None;
        let mut last_dns_error = None;
        for offset in 0..self.upstreams.len() {
            let index = (start + offset) % self.upstreams.len();
            match self.exchange_one(index, query, retry_without_ecs).await {
                Ok(response) if wire::response_is_success(&response.bytes)? => return Ok(response),
                Ok(response) => last_dns_error = Some(response),
                Err(err) => last_error = Some(err),
            }
        }
        last_dns_error.map_or_else(
            || {
                Err(last_error
                    .unwrap_or_else(|| Error::RustError("no DNS upstream available".into())))
            },
            Ok,
        )
    }

    async fn exchange_one(
        &self,
        index: usize,
        query: &[u8],
        retry_without_ecs: Option<&[u8]>,
    ) -> Result<UpstreamResponse> {
        let upstream = self
            .upstreams
            .get(index)
            .ok_or_else(|| Error::RustError("DNS upstream index is out of range".into()))?;
        let timeout_ms = upstream.timeout_ms.unwrap_or(self.timeout_ms);
        with_timeout(timeout_ms, async {
            let bytes = self.exchange_one_query(index, query).await?;
            if let Some(retry_query) = retry_without_ecs
                && wire::parse_message(&bytes)?.rcode == OptRcode::REFUSED
            {
                return Ok(self.exchange_one_query(index, retry_query).await.map_or(
                    UpstreamResponse {
                        bytes,
                        retried_without_ecs: true,
                    },
                    |bytes| UpstreamResponse {
                        bytes,
                        retried_without_ecs: true,
                    },
                ));
            }
            Ok(UpstreamResponse {
                bytes,
                retried_without_ecs: false,
            })
        })
        .await
        .unwrap_or_else(|| Err(timeout_error("DNS upstream", timeout_ms)))
    }

    async fn exchange_one_query(&self, index: usize, query: &[u8]) -> Result<Vec<u8>> {
        let upstream = self
            .upstreams
            .get(index)
            .ok_or_else(|| Error::RustError("DNS upstream index is out of range".into()))?;
        match &upstream.transport {
            Transport::Https { url } => {
                let headers = Headers::new();
                headers.set("accept", "application/dns-message")?;
                headers.set("content-type", "application/dns-message")?;

                let mut init = RequestInit::new();
                init.with_method(Method::Post)
                    .with_redirect(worker::RequestRedirect::Manual)
                    .with_headers(headers)
                    .with_body(Some(JsValue::from(js_sys::Uint8Array::from(query))));

                let request = Request::new_with_init(url, &init)?;
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

                if !response
                    .headers()
                    .get("content-type")?
                    .ok_or_else(|| {
                        Error::RustError("DNS HTTPS upstream omitted Content-Type".into())
                    })?
                    .split(';')
                    .next()
                    .is_some_and(|value| {
                        value.trim().eq_ignore_ascii_case("application/dns-message")
                    })
                {
                    return Err(Error::RustError(
                        "DNS HTTPS upstream returned an unexpected Content-Type".into(),
                    ));
                }

                if let Some(length) = response
                    .headers()
                    .get("content-length")?
                    .map(|length| {
                        length.parse::<usize>().map_err(|_| {
                            Error::RustError(
                                "DNS HTTPS upstream returned an invalid Content-Length".into(),
                            )
                        })
                    })
                    .transpose()?
                    && length > self.max_message_bytes
                {
                    return Err(Error::RustError(
                        "DNS upstream response is too large".into(),
                    ));
                }
                let age = match response.headers().get("age")? {
                    Some(value) => value
                        .parse::<u64>()
                        .map(|age| age.min(u64::from(u32::MAX)) as u32)
                        .map_err(|_| {
                            Error::RustError("DNS HTTPS upstream returned an invalid Age".into())
                        })?,
                    None => 0,
                };
                let mut bytes = read_body(response.stream()?, self.max_message_bytes).await?;
                wire::validate_response(query, &bytes)?;
                #[allow(clippy::cast_sign_loss)]
                let elapsed_seconds =
                    ((js_sys::Date::now() - received_at) / 1000.0).max(0.0) as u32;
                wire::age(&mut bytes, age.saturating_add(elapsed_seconds))?;
                abort_on_drop.0.take();
                Ok(bytes)
            }
            Transport::Tls { host, port } => {
                exchange_socket(host, *port, true, query, self.max_message_bytes).await
            }
            Transport::Tcp { host, port } => {
                exchange_socket(host, *port, false, query, self.max_message_bytes).await
            }
        }
    }
}

async fn exchange_socket(
    host: &str,
    port: u16,
    tls: bool,
    query: &[u8],
    max_message_bytes: usize,
) -> Result<Vec<u8>> {
    let socket = if tls {
        Socket::builder()
            .secure_transport(worker::SecureTransport::On)
            .connect(host.to_string(), port)?
    } else {
        Socket::builder().connect(host.to_string(), port)?
    };
    let mut socket = SocketOnDrop(Some(socket));

    let result = async {
        let socket = socket
            .0
            .as_mut()
            .ok_or_else(|| Error::RustError("DNS upstream socket is unavailable".into()))?;
        socket.opened().await?;
        let length = u16::try_from(query.len())
            .map_err(|_| Error::RustError("DNS query too large".into()))?;
        socket.write_all(&length.to_be_bytes()).await?;
        socket.write_all(query).await?;
        socket.flush().await?;

        let response_len = socket.read_u16().await? as usize;
        if response_len > max_message_bytes {
            return Err(Error::RustError(
                "DNS upstream response is too large".into(),
            ));
        }
        let mut response = vec![0_u8; response_len];
        socket.read_exact(&mut response).await?;
        wire::validate_response(query, &response)?;
        Ok(response)
    }
    .await;
    drop(match socket.0.as_mut() {
        Some(socket) => socket.close().await,
        None => Ok(()),
    });
    socket.0.take();
    result
}

async fn with_timeout<F>(timeout_ms: u32, future: F) -> Option<F::Output>
where
    F: Future,
{
    let future = future.fuse();
    let timer = Delay::from(Duration::from_millis(u64::from(timeout_ms))).fuse();
    futures_util::pin_mut!(future, timer);
    match select(future, timer).await {
        futures_util::future::Either::Left((result, _)) => Some(result),
        futures_util::future::Either::Right(((), _)) => None,
    }
}

fn timeout_error(kind: &str, timeout_ms: u32) -> Error {
    Error::RustError(format!("{kind} timed out after {timeout_ms} ms"))
}

struct AbortOnDrop(Option<AbortController>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        if let Some(controller) = self.0.take() {
            controller.abort();
        }
    }
}

struct SocketOnDrop(Option<Socket>);

impl Drop for SocketOnDrop {
    fn drop(&mut self) {
        if let Some(mut socket) = self.0.take() {
            drop(socket.close().now_or_never());
        }
    }
}
