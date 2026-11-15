use std::{cell::RefCell, rc::Rc};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use domain::base::iana::OptRcode;
use futures_util::{StreamExt, stream::FuturesUnordered};
use sha2::{Digest, Sha256};
use worker::{Error, Result, Socket};

use crate::util::with_timeout;

use crate::dns::{
    DnsError, DnsResult, DnsService,
    cache::DnsCache,
    config::{self, DnsConfig, Strategy},
    inbound, wire,
};

use super::{SocketOnDrop, Transport, UpstreamResponse};

const PROBE_TIMEOUT_MS: u32 = 1_000;

type ProbeOrder = Option<(Rc<str>, Rc<[usize]>)>;

thread_local! {
    static PROBE_ORDER: RefCell<ProbeOrder> = const { RefCell::new(None) };
}

#[derive(Clone)]
pub(in crate::dns) struct UpstreamPool {
    upstreams: Rc<[Transport]>,
    strategy: Strategy,
    timeout_ms: u32,
    request_timeout_ms: u32,
    race_concurrency: usize,
    probe: Option<Rc<[u16]>>,
    max_message_bytes: usize,
    probe_key: Rc<str>,
    probe_order_cache: Rc<RefCell<Option<Rc<[usize]>>>>,
}

impl DnsService {
    #[allow(clippy::single_call_fn)]
    pub(crate) fn new(config: DnsConfig, origin: &str) -> Result<Self> {
        let probe_key = Rc::from(format!("{origin}\0{}", serde_json::to_string(&config)?));

        if config.servers.is_empty() {
            return Err(Error::RustError(
                "invalid DNS config: servers must contain at least one DNS server".into(),
            ));
        }
        if config.servers.len() > 16 {
            return Err(Error::RustError(
                "invalid DNS config: servers may contain at most 16 DNS servers".into(),
            ));
        }
        let mut server_tags = std::collections::HashSet::new();
        for server in &config.servers {
            if let Some(tag) = &server.tag
                && (tag.trim().is_empty() || tag.trim() != tag || !server_tags.insert(tag))
            {
                return Err(Error::RustError(
                    "invalid DNS config: DNS server tags must be nonempty and unique".into(),
                ));
            }
        }
        config::validate_timeout("timeout_ms", config.timeout_ms)?;
        config::validate_timeout("request_timeout_ms", config.request_timeout_ms)?;
        if !(1..=6).contains(&config.race_concurrency) {
            return Err(Error::RustError(
                "invalid DNS config: race_concurrency must be between 1 and 6".into(),
            ));
        }
        config::validate_message_size("max_message_bytes", config.max_message_bytes)?;

        if let Some(ecs) = &config.ecs {
            if ecs.ipv4_prefix > 32 {
                return Err(Error::RustError(
                    "invalid DNS config: ecs.ipv4_prefix must not exceed 32".into(),
                ));
            }
            if ecs.ipv6_prefix > 128 {
                return Err(Error::RustError(
                    "invalid DNS config: ecs.ipv6_prefix must not exceed 128".into(),
                ));
            }
        }

        if let Some(cache) = &config.cache {
            if !(1..=86_400).contains(&cache.max_ttl) {
                return Err(Error::RustError(
                    "invalid DNS config: cache.max_ttl must be between 1 and 86400".into(),
                ));
            }
            config::validate_message_size("cache.max_message_bytes", cache.max_message_bytes)?;
        }

        let inbound_config = inbound::Config::new(&config);
        Ok(Self {
            upstreams: UpstreamPool {
                upstreams: Rc::from(
                    config
                        .servers
                        .iter()
                        .map(Transport::from_config)
                        .collect::<Result<Vec<_>>>()?,
                ),
                strategy: config.strategy,
                timeout_ms: config.timeout_ms,
                request_timeout_ms: config.request_timeout_ms,
                race_concurrency: config.race_concurrency,
                probe: config.probe.as_deref().map(|value| {
                    Rc::from(
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
                            .collect::<Vec<_>>(),
                    )
                }),
                max_message_bytes: config.max_message_bytes,
                probe_key: Rc::clone(&probe_key),
                probe_order_cache: Rc::new(RefCell::new(PROBE_ORDER.with(|order| {
                    order.borrow().as_ref().and_then(|(key, order)| {
                        (key.as_ref() == probe_key.as_ref()).then(|| Rc::clone(order))
                    })
                }))),
            },
            cache: config
                .cache
                .as_ref()
                .map(|cache_config| -> Result<Rc<DnsCache>> {
                    let mut hash = Sha256::new();
                    hash.update(b"cfwp-dns-v1\0");
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
            inbound: inbound_config,
        })
    }
}

impl UpstreamPool {
    pub(in crate::dns) async fn exchange(
        &self,
        query: &[u8],
        retry_without_ecs: Option<&[u8]>,
    ) -> DnsResult<UpstreamResponse> {
        let operation = async {
            match self.strategy {
                Strategy::None => Ok(self.exchange_in_order(query, retry_without_ecs, 0).await?),
                Strategy::FastestV4 | Strategy::FastestV6 | Strategy::FastestAll => {
                    let start = 'probe: {
                        let Some(probes) = self.probe.as_deref() else {
                            break 'probe 0;
                        };
                        if let Some(order) = self.probe_order_cache.borrow().as_ref()
                            && let Some(&first) = order.first()
                        {
                            break 'probe first;
                        }
                        if probes.is_empty() {
                            break 'probe 0;
                        }
                        let mut latencies = Vec::new();
                        let probe_budget =
                            f64::from(self.request_timeout_ms / 2).max(f64::from(PROBE_TIMEOUT_MS));
                        let probe_started = js_sys::Date::now();
                        for (index, transport) in self.upstreams.iter().enumerate() {
                            let Some((host, _)) = transport.probe_target() else {
                                latencies.push((index, None));
                                continue;
                            };
                            let mut latency = None;
                            for port in probes {
                                let remaining =
                                    probe_budget - (js_sys::Date::now() - probe_started);
                                if remaining <= 0.0 {
                                    break;
                                }
                                let deadline = remaining.min(f64::from(PROBE_TIMEOUT_MS));
                                #[allow(clippy::cast_sign_loss)]
                                let ms = with_timeout(deadline as u32, async {
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
                                })
                                .await
                                .flatten();
                                if let Some(ms) = ms {
                                    tracing::info!("DNS probe {host}:{port} -> {ms} ms");
                                    latency = Some(ms);
                                    break;
                                }
                            }
                            latencies.push((index, latency));
                        }
                        latencies
                            .sort_by_key(|(index, latency)| (latency.unwrap_or(u32::MAX), *index));
                        let order = latencies
                            .into_iter()
                            .map(|(index, _)| index)
                            .collect::<Rc<[usize]>>();
                        let first = order.first().copied().unwrap_or(0);
                        *self.probe_order_cache.borrow_mut() = Some(Rc::clone(&order));
                        PROBE_ORDER.with(|cache| {
                            *cache.borrow_mut() =
                                Some((Rc::clone(&self.probe_key), Rc::clone(&order)));
                        });
                        first
                    };
                    Ok(self
                        .exchange_in_order(query, retry_without_ecs, start)
                        .await?)
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
                            Ok(response)
                                if matches!(
                                    wire::parse_message(&response.bytes)?.rcode,
                                    OptRcode::NOERROR | OptRcode::NXDOMAIN
                                ) =>
                            {
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

                    Ok(last_dns_error.map_or_else(
                        || {
                            Err(last_error.unwrap_or_else(|| {
                                Error::RustError("no DNS upstream available".into())
                            }))
                        },
                        Ok,
                    )?)
                }
            }
        };
        with_timeout(self.request_timeout_ms, operation)
            .await
            .unwrap_or_else(|| Err(DnsError::Timeout(self.request_timeout_ms)))
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
                Ok(response)
                    if matches!(
                        wire::parse_message(&response.bytes)?.rcode,
                        OptRcode::NOERROR | OptRcode::NXDOMAIN
                    ) =>
                {
                    return Ok(response);
                }
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
        let timeout_ms = self.timeout_ms;
        with_timeout(timeout_ms, async {
            let bytes = self.exchange_one_query(index, query).await?;
            if let Some(retry_query) = retry_without_ecs
                && wire::parse_message(&bytes)?.rcode == OptRcode::REFUSED
            {
                return Ok(self.exchange_one_query(index, retry_query).await.map_or(
                    UpstreamResponse {
                        bytes,
                        retried_without_ecs: false,
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
        .unwrap_or_else(|| {
            Err(Error::RustError(format!(
                "DNS upstream timed out after {timeout_ms} ms"
            )))
        })
    }

    async fn exchange_one_query(&self, index: usize, query: &[u8]) -> Result<Vec<u8>> {
        let transport = self
            .upstreams
            .get(index)
            .ok_or_else(|| Error::RustError("DNS upstream index is out of range".into()))?;
        super::exchange(transport, query, self.max_message_bytes).await
    }
}
