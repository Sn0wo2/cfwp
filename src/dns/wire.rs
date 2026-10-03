use std::{net::IpAddr, time::Duration};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use domain::base::iana::{Opcode, OptRcode, Rtype};
use domain::base::message::Section;
use domain::base::opt::{ClientSubnet, ComposeOptData, UnknownOptData};
use domain::base::{Message, ParsedName};
use domain::rdata::AllRecordData;
use futures_util::{FutureExt, future::select};
use sha2::{Digest, Sha256};
use worker::{Cache, Delay, Error, Headers, Response, Result};

use super::{DnsService, config::AddressFamily, util::read_body};

const DNS_MAX_MESSAGE_LEN: usize = u16::MAX as usize;
const DEFAULT_UDP_PAYLOAD_SIZE: u16 = 1232;
const EDNS_OPT_RTYPE: u16 = 41;
const EDNS_OPTION_ECS: u16 = 8;
const EDNS_OPTION_PADDING: u16 = 12;

pub(crate) struct Prepared {
    pub(super) bytes: Vec<u8>,
    pub(super) injected: bool,
    pub(super) cacheable: bool,
    original: Option<Vec<u8>>,
    local_response: bool,
    question_type: Option<Rtype>,
    question_type_offset: Option<usize>,
    question_end: usize,
}

#[derive(Clone, Copy)]
struct OptInfo {
    rdlen_offset: usize,
    rdlen: usize,
    end: usize,
}

#[derive(Clone, Copy)]
struct RecordInfo {
    section: Section,
    rtype: Rtype,
    ttl: u32,
    ttl_offset: usize,
    soa_minimum: Option<u32>,
}

pub(super) struct ParsedMessage {
    qr: bool,
    opcode: Opcode,
    truncated: bool,
    question_count: u16,
    answer_count: u16,
    pub(super) rcode: OptRcode,
    has_ecs: bool,
    ecs_ranges: Vec<(usize, usize)>,
    has_cookie: bool,
    signed: bool,
    question_types: Vec<Rtype>,
    question_type_offsets: Vec<usize>,
    question_end: usize,
    opt: Option<OptInfo>,
    records: Vec<RecordInfo>,
}

#[allow(clippy::multiple_inherent_impl)]
impl DnsService {
    pub(crate) fn prepare(&self, payload: &[u8], client_ip: Option<IpAddr>) -> Result<Prepared> {
        if payload.len() > self.config.max_message_bytes {
            return Err(Error::RustError("DNS query too large".into()));
        }

        let parsed = parse_message(payload)?;
        if parsed.qr {
            return Err(wire_error("expected a DNS query"));
        }
        if parsed.opcode != Opcode::QUERY {
            return Err(wire_error("only standard DNS queries are supported"));
        }
        if parsed.question_count == 0 {
            return Err(wire_error("DNS query has no question"));
        }

        let policy = self.config.address_family;
        let blocked = match policy {
            AddressFamily::OnlyV4 => parsed.question_types.contains(&Rtype::AAAA),
            AddressFamily::OnlyV6 => parsed.question_types.contains(&Rtype::A),
            _ => false,
        };
        if blocked {
            if parsed.question_count != 1 {
                return Err(wire_error(
                    "address-family filtering requires a single-question DNS query",
                ));
            }
            if parsed.signed {
                return Err(wire_error(
                    "cannot synthesize an address-family response for a signed DNS query",
                ));
            }
            return Ok(Prepared {
                bytes: make_nodata_response(payload, parsed.question_end)?,
                injected: false,
                cacheable: false,
                original: None,
                local_response: true,
                question_type: None,
                question_type_offset: None,
                question_end: parsed.question_end,
            });
        }

        let preferred_type = match policy {
            AddressFamily::PerfV4 if parsed.question_types.contains(&Rtype::AAAA) => Some(Rtype::A),
            AddressFamily::PerfV6 if parsed.question_types.contains(&Rtype::A) => Some(Rtype::AAAA),
            _ => None,
        };
        if preferred_type.is_some() {
            if parsed.question_count != 1 {
                return Err(wire_error(
                    "address-family preference requires a single-question DNS query",
                ));
            }
            if parsed.signed {
                return Err(wire_error(
                    "cannot rewrite a signed DNS query for address-family preference",
                ));
            }
        }

        let mut bytes = payload.to_vec();
        let mut injected = false;
        let mut cacheable = !parsed.signed && !parsed.has_cookie;

        if !parsed.signed
            && !parsed.has_ecs
            && let (Some(client_ip), Some(ecs)) = (client_ip, self.config.ecs.as_ref())
        {
            let subnet = ClientSubnet::new(
                match client_ip {
                    IpAddr::V4(_) => ecs.ipv4_prefix.min(32),
                    IpAddr::V6(_) => ecs.ipv6_prefix.min(128),
                },
                0,
                client_ip,
            );
            let mut data = Vec::with_capacity(usize::from(subnet.compose_len()));
            subnet
                .compose_option(&mut data)
                .map_err(|_| wire_error("failed to compose EDNS client subnet"))?;
            let mut option = Vec::with_capacity(4 + data.len());
            option.extend_from_slice(&EDNS_OPTION_ECS.to_be_bytes());
            option.extend_from_slice(
                &u16::try_from(data.len())
                    .map_err(|_| wire_error("EDNS client subnet is too large"))?
                    .to_be_bytes(),
            );
            option.extend_from_slice(&data);

            if let Some(opt) = parsed.opt {
                if opt.end != bytes.len() {
                    cacheable = false;
                } else if let Some(new_rdlen) = opt.rdlen.checked_add(option.len()) {
                    if new_rdlen > usize::from(u16::MAX)
                        || bytes
                            .len()
                            .checked_add(option.len())
                            .is_none_or(|len| len > DNS_MAX_MESSAGE_LEN)
                    {
                        cacheable = false;
                    } else if let Ok(new_rdlen) = u16::try_from(new_rdlen) {
                        bytes.extend_from_slice(&option);
                        bytes
                            .get_mut(opt.rdlen_offset..opt.rdlen_offset + 2)
                            .ok_or_else(|| wire_error("EDNS resource-data length out of range"))?
                            .copy_from_slice(&new_rdlen.to_be_bytes());
                        injected = true;
                    } else {
                        cacheable = false;
                    }
                } else {
                    cacheable = false;
                }
            } else {
                let arcount = bytes
                    .get(10..12)
                    .and_then(|bytes| bytes.try_into().ok())
                    .map(u16::from_be_bytes)
                    .ok_or_else(|| wire_error("DNS additional-record count out of range"))?;
                if arcount == u16::MAX
                    || bytes
                        .len()
                        .checked_add(11 + option.len())
                        .is_none_or(|new_len| new_len > DNS_MAX_MESSAGE_LEN)
                    || option.len() > usize::from(u16::MAX)
                {
                    cacheable = false;
                } else if let Ok(rdlen) = u16::try_from(option.len()) {
                    bytes.push(0);
                    bytes.extend_from_slice(&EDNS_OPT_RTYPE.to_be_bytes());
                    bytes.extend_from_slice(&DEFAULT_UDP_PAYLOAD_SIZE.to_be_bytes());
                    bytes.extend_from_slice(&0_u32.to_be_bytes());
                    bytes.extend_from_slice(&rdlen.to_be_bytes());
                    bytes.extend_from_slice(&option);
                    bytes
                        .get_mut(10..12)
                        .ok_or_else(|| wire_error("DNS additional-record count out of range"))?
                        .copy_from_slice(&(arcount + 1).to_be_bytes());
                    injected = true;
                } else {
                    cacheable = false;
                }
            }
        }

        if bytes.len() > self.config.max_message_bytes {
            return Err(Error::RustError(
                "DNS query too large after ECS injection".into(),
            ));
        }

        Ok(Prepared {
            bytes,
            injected,
            cacheable,
            original: injected.then(|| payload.to_vec()),
            local_response: false,
            question_type: parsed.question_types.first().copied(),
            question_type_offset: parsed.question_type_offsets.first().copied(),
            question_end: parsed.question_end,
        })
    }

    pub(crate) async fn exchange_prepared(&self, prepared: Prepared) -> Result<Vec<u8>> {
        if prepared.local_response {
            return Ok(prepared.bytes);
        }

        let preferred_type = match (self.config.address_family, prepared.question_type) {
            (AddressFamily::PerfV4, Some(Rtype::AAAA)) => Some(Rtype::A),
            (AddressFamily::PerfV6, Some(Rtype::A)) => Some(Rtype::AAAA),
            _ => None,
        };
        if let Some(preferred_type) = preferred_type {
            let offset = prepared
                .question_type_offset
                .ok_or_else(|| wire_error("missing DNS question type offset"))?;
            let mut probe_bytes = prepared.bytes.clone();
            write_u16(&mut probe_bytes, offset, u16::from(preferred_type))?;
            let mut probe_original = prepared.original.clone();
            if let Some(original) = &mut probe_original {
                write_u16(original, offset, u16::from(preferred_type))?;
            }
            let probe = Prepared {
                bytes: probe_bytes,
                injected: prepared.injected,
                cacheable: prepared.cacheable,
                original: probe_original,
                local_response: false,
                question_type: Some(preferred_type),
                question_type_offset: prepared.question_type_offset,
                question_end: prepared.question_end,
            };
            return self
                .exchange_preferred(prepared, probe, preferred_type)
                .await;
        }

        self.exchange_query(prepared).await
    }

    async fn exchange_preferred(
        &self,
        fallback: Prepared,
        probe: Prepared,
        preferred_type: Rtype,
    ) -> Result<Vec<u8>> {
        let fallback_query = fallback.bytes.clone();
        let question_end = fallback.question_end;
        let timeout_ms = self.config.request_timeout_ms;
        let timer = Delay::from(Duration::from_millis(u64::from(timeout_ms))).fuse();
        futures_util::pin_mut!(timer);
        let fallback = Box::pin(self.exchange_query(fallback));
        let probe = Box::pin(self.exchange_query(probe));

        match select(fallback, probe).await {
            futures_util::future::Either::Left((fallback_result, probe)) => {
                match select(probe, timer).await {
                    futures_util::future::Either::Left((probe_result, _)) => {
                        if let Ok(response) = probe_result
                            && response_has_address_answer(&response, preferred_type)?
                        {
                            return make_nodata_response(&fallback_query, question_end);
                        }
                    }
                    futures_util::future::Either::Right(((), _)) => {}
                }
                fallback_result
            }
            futures_util::future::Either::Right((probe_result, fallback)) => {
                if let Ok(response) = probe_result
                    && response_has_address_answer(&response, preferred_type)?
                {
                    return make_nodata_response(&fallback_query, question_end);
                }
                match select(fallback, timer).await {
                    futures_util::future::Either::Left((fallback_result, _)) => fallback_result,
                    futures_util::future::Either::Right(((), _)) => Err(Error::RustError(format!(
                        "DNS request timed out after {timeout_ms} ms"
                    ))),
                }
            }
        }
    }

    async fn exchange_query(&self, prepared: Prepared) -> Result<Vec<u8>> {
        let cache_key = self
            .cache
            .as_ref()
            .filter(|_| prepared.cacheable)
            .map(|cache| {
                let query = prepared
                    .bytes
                    .get(2..)
                    .ok_or_else(|| wire_error("DNS query header out of range"))?;
                Ok::<_, Error>(format!(
                    "{}{}",
                    cache.prefix,
                    URL_SAFE_NO_PAD.encode(Sha256::digest(query))
                ))
            })
            .transpose()?;
        let mut response = None;
        if let (Some(_), Some(key)) = (&self.cache, &cache_key) {
            match async {
                let cache = Cache::open("cfwp-dns".into()).await;
                let Some(mut cached) = cache.get(key, false).await? else {
                    return Ok::<Option<Vec<u8>>, Error>(None);
                };
                let stored = cached
                    .headers()
                    .get("x-cfwp-stored-at")?
                    .and_then(|value| value.parse::<f64>().ok());
                let ttl = cached
                    .headers()
                    .get("x-cfwp-ttl")?
                    .and_then(|value| value.parse::<u32>().ok());
                let (Some(stored), Some(ttl)) = (stored, ttl) else {
                    return Ok(None);
                };
                #[allow(clippy::cast_sign_loss)]
                let elapsed = ((js_sys::Date::now() - stored) / 1000.0).max(0.0) as u32;
                if elapsed >= ttl {
                    return Ok(None);
                }
                let mut bytes = read_body(cached.stream()?, self.config.max_message_bytes).await?;
                if bytes.len() < 12 {
                    return Ok(None);
                }
                let response_id = bytes
                    .get_mut(..2)
                    .ok_or_else(|| wire_error("DNS response ID out of range"))?;
                let query_id = prepared
                    .bytes
                    .get(..2)
                    .ok_or_else(|| wire_error("DNS query ID out of range"))?;
                response_id.copy_from_slice(query_id);
                validate_response(&prepared.bytes, &bytes)?;
                age(&mut bytes, elapsed)?;
                Ok(Some(bytes))
            }
            .await
            {
                Ok(cached) => response = cached,
                Err(err) => acta::info!("DNS cache read failed: {err}"),
            }
        }
        let mut response = match response {
            Some(response) => response,
            None => {
                let result = self
                    .upstreams
                    .exchange(
                        &prepared.bytes,
                        prepared.original.as_deref().filter(|_| {
                            self.config
                                .ecs
                                .as_ref()
                                .is_some_and(|ecs| ecs.retry_without_ecs)
                        }),
                    )
                    .await?;
                let response = result.bytes;
                if !result.retried_without_ecs
                    && let (Some(cache), Some(key)) = (&self.cache, cache_key)
                    && let Err(err) = async {
                        if response.len() > cache.config.max_message_bytes {
                            return Ok(());
                        }
                        let parsed = parse_message(&response)?;
                        let ttl = if !parsed.qr
                            || parsed.truncated
                            || parsed.signed
                            || parsed.has_cookie
                            || (parsed.rcode != OptRcode::NOERROR
                                && parsed.rcode != OptRcode::NXDOMAIN)
                        {
                            None
                        } else if parsed.answer_count > 0 && parsed.rcode == OptRcode::NOERROR {
                            parsed
                                .records
                                .iter()
                                .filter(|record| record.rtype != Rtype::OPT)
                                .map(|record| record.ttl)
                                .min()
                        } else {
                            let negative_ttl = parsed
                                .records
                                .iter()
                                .filter(|record| record.section == Section::Authority)
                                .filter_map(|record| {
                                    record.soa_minimum.map(|minimum| record.ttl.min(minimum))
                                })
                                .min();
                            let record_ttl = parsed
                                .records
                                .iter()
                                .filter(|record| record.rtype != Rtype::OPT)
                                .map(|record| record.ttl)
                                .min();
                            negative_ttl.map(|ttl| ttl.min(record_ttl.unwrap_or(ttl)))
                        };
                        let Some(ttl) = ttl else {
                            return Ok(());
                        };
                        let ttl = ttl.min(cache.config.max_ttl);
                        if ttl == 0 {
                            return Ok(());
                        }
                        let headers = Headers::new();
                        headers.set("content-type", "application/dns-message")?;
                        headers.set("cache-control", &format!("public, max-age={ttl}"))?;
                        headers.set("x-cfwp-stored-at", &js_sys::Date::now().to_string())?;
                        headers.set("x-cfwp-ttl", &ttl.to_string())?;
                        Cache::open("cfwp-dns".into())
                            .await
                            .put(
                                key,
                                Response::from_bytes(response.to_vec())?.with_headers(headers),
                            )
                            .await
                    }
                    .await
                {
                    acta::info!("DNS cache write failed: {err}");
                }
                response
            }
        };
        if prepared.injected
            && self
                .config
                .ecs
                .as_ref()
                .is_some_and(|ecs| ecs.strip_injected)
        {
            let parsed = parse_message(&response)?;
            if !parsed.signed
                && let Some(opt) = parsed.opt
            {
                let ranges = parsed.ecs_ranges;
                if !ranges.is_empty() {
                    if opt.end == response.len() {
                        let removed = ranges.iter().map(|(start, end)| end - start).sum::<usize>();
                        for (start, end) in ranges.into_iter().rev() {
                            response.drain(start..end);
                        }
                        write_u16(
                            &mut response,
                            opt.rdlen_offset,
                            opt.rdlen
                                .checked_sub(removed)
                                .ok_or_else(|| wire_error("invalid ECS option length"))?
                                as u16,
                        )?;
                    } else {
                        for (start, end) in ranges {
                            write_u16(&mut response, start, EDNS_OPTION_PADDING)?;
                            response
                                .get_mut(start + 4..end)
                                .ok_or_else(|| wire_error("EDNS padding range out of bounds"))?
                                .fill(0);
                        }
                    }
                    parse_message(&response)?;
                }
            }
        }
        Ok(response)
    }
}

pub(super) fn validate_response(query: &[u8], response: &[u8]) -> Result<()> {
    let query_message =
        Message::from_slice(query).map_err(|_| wire_error("malformed DNS query header"))?;
    let response_info = parse_message(response)?;
    if !response_info.qr || response_info.opcode != query_message.header().opcode() {
        return Err(wire_error("DNS response header does not match query"));
    }

    let response_message =
        Message::from_slice(response).map_err(|_| wire_error("malformed DNS response header"))?;
    if !response_message.is_answer(query_message) {
        return Err(wire_error("DNS response does not match query"));
    }
    Ok(())
}

pub(super) fn age(response: &mut [u8], seconds: u32) -> Result<()> {
    if seconds == 0 {
        return Ok(());
    }
    let parsed = parse_message(response)?;
    if parsed.signed {
        return Ok(());
    }
    for record in parsed.records {
        if record.rtype == Rtype::OPT {
            continue;
        }
        let dst = response
            .get_mut(record.ttl_offset..record.ttl_offset + 4)
            .ok_or_else(|| wire_error("DNS field offset out of range"))?;
        dst.copy_from_slice(&record.ttl.saturating_sub(seconds).to_be_bytes());
    }
    Ok(())
}

pub(super) fn parse_message(payload: &[u8]) -> Result<ParsedMessage> {
    if payload.len() > DNS_MAX_MESSAGE_LEN {
        return Err(wire_error("DNS message is too large"));
    }
    let message = Message::from_slice(payload)
        .map_err(|_| wire_error("DNS message is shorter than its header"))?;

    let mut questions = message.question();
    let mut question_types = Vec::new();
    let mut question_type_offsets = Vec::new();
    while let Some(question) = questions.next() {
        let question = question.map_err(|_| wire_error("malformed DNS question"))?;
        let offset = questions
            .pos()
            .checked_sub(4)
            .ok_or_else(|| wire_error("invalid DNS question offset"))?;
        question_types.push(question.qtype());
        question_type_offsets.push(offset);
    }
    let question_end = questions.pos();

    let counts = message.header_counts();
    let mut records = Vec::new();
    let mut opt = None;
    let mut opt_count = 0_usize;
    let mut ext_rcode = 0_u8;
    let mut has_ecs = false;
    let mut ecs_ranges = Vec::new();
    let mut has_cookie = false;
    let mut signed = false;
    let mut section = message
        .answer()
        .map_err(|_| wire_error("malformed DNS answer section"))?;

    for section_kind in [Section::Answer, Section::Authority, Section::Additional] {
        while let Some(record) = section.next() {
            let record = record.map_err(|_| wire_error("malformed DNS resource record"))?;
            let end = section.pos();
            let rtype = record.rtype();
            let rdlen = usize::from(record.rdlen());
            let rdata_start = end
                .checked_sub(rdlen)
                .ok_or_else(|| wire_error("invalid DNS resource-data length"))?;
            let rdlen_offset = rdata_start
                .checked_sub(2)
                .ok_or_else(|| wire_error("invalid DNS resource-data offset"))?;
            let ttl_offset = rdata_start
                .checked_sub(6)
                .ok_or_else(|| wire_error("invalid DNS TTL offset"))?;
            let ttl = record.ttl().as_secs();
            let owner_is_root = record.owner().is_root();

            let parsed_rr = record
                .to_any_record::<AllRecordData<&[u8], ParsedName<&[u8]>>>()
                .map_err(|_| wire_error("malformed DNS resource data"))?;
            let rdata = parsed_rr.into_data();

            if rtype == Rtype::TSIG
                || (rtype == Rtype::SIG
                    && rdlen >= 2
                    && payload.get(rdata_start..rdata_start + 2) == Some(&[0, 0][..]))
            {
                signed = true;
            }

            let mut soa_minimum = None;
            if rtype == Rtype::OPT {
                if section_kind != Section::Additional || !owner_is_root {
                    return Err(wire_error("invalid EDNS OPT record"));
                }
                opt_count += 1;
                if opt_count > 1 {
                    return Err(wire_error("multiple EDNS OPT records"));
                }
                ext_rcode = (ttl >> 24) as u8;
                let AllRecordData::Opt(options) = rdata else {
                    return Err(wire_error("malformed EDNS OPT data"));
                };
                let mut option_pos = rdata_start;
                for option in options.iter::<UnknownOptData<&[u8]>>() {
                    let option = option.map_err(|_| wire_error("malformed EDNS option"))?;
                    let option_end = option_pos + 4 + option.as_slice().len();
                    match u16::from(option.code()) {
                        EDNS_OPTION_ECS => {
                            has_ecs = true;
                            ecs_ranges.push((option_pos, option_end));
                        }
                        10 => has_cookie = true,
                        _ => {}
                    }
                    option_pos = option_end;
                }
                opt = Some(OptInfo {
                    rdlen_offset,
                    rdlen,
                    end,
                });
            } else if rtype == Rtype::SOA {
                match rdata {
                    AllRecordData::Soa(soa) => {
                        soa_minimum = Some(soa.minimum().as_secs());
                    }
                    _ => return Err(wire_error("malformed SOA resource data")),
                }
            }

            records.push(RecordInfo {
                section: section_kind,
                rtype,
                ttl,
                ttl_offset,
                soa_minimum,
            });
        }

        if section_kind == Section::Additional {
            if section.pos() != payload.len() {
                return Err(wire_error("trailing bytes after DNS sections"));
            }
        } else {
            section = section
                .next_section()
                .map_err(|_| wire_error("malformed DNS record section"))?
                .ok_or_else(|| wire_error("missing DNS record section"))?;
        }
    }

    Ok(ParsedMessage {
        qr: message.header().qr(),
        opcode: message.header().opcode(),
        truncated: message.header().tc(),
        question_count: counts.qdcount(),
        answer_count: counts.ancount(),
        rcode: OptRcode::from_parts(message.header().rcode(), ext_rcode),
        has_ecs,
        ecs_ranges,
        has_cookie,
        signed,
        question_types,
        question_type_offsets,
        question_end,
        opt,
        records,
    })
}

pub(super) fn response_is_success(response: &[u8]) -> Result<bool> {
    let rcode = parse_message(response)?.rcode;
    Ok(rcode == OptRcode::NOERROR || rcode == OptRcode::NXDOMAIN)
}

fn response_has_address_answer(response: &[u8], address_type: Rtype) -> Result<bool> {
    let parsed = parse_message(response)?;
    Ok(parsed.rcode == OptRcode::NOERROR
        && parsed
            .records
            .iter()
            .any(|record| record.section == Section::Answer && record.rtype == address_type))
}

fn make_nodata_response(query: &[u8], question_end: usize) -> Result<Vec<u8>> {
    if query.len() < 12 || !(12..=query.len()).contains(&question_end) {
        return Err(wire_error("invalid DNS question bounds"));
    }
    let parsed = parse_message(query)?;
    let mut response = query
        .get(..question_end)
        .ok_or_else(|| wire_error("invalid DNS question bounds"))?
        .to_vec();
    let query_flags = query
        .get(2..4)
        .and_then(|flags| flags.try_into().ok())
        .map(u16::from_be_bytes)
        .ok_or_else(|| wire_error("DNS query flags out of range"))?;
    let response_flags = (query_flags & 0x7800) | (query_flags & 0x0100) | 0x8080;
    response
        .get_mut(2..4)
        .ok_or_else(|| wire_error("DNS response flags out of range"))?
        .copy_from_slice(&response_flags.to_be_bytes());
    response
        .get_mut(6..12)
        .ok_or_else(|| wire_error("DNS response counts out of range"))?
        .fill(0);
    if let Some(opt) = parsed.opt {
        let class_offset = opt
            .rdlen_offset
            .checked_sub(6)
            .ok_or_else(|| wire_error("invalid EDNS class offset"))?;
        let ttl_offset = opt
            .rdlen_offset
            .checked_sub(4)
            .ok_or_else(|| wire_error("invalid EDNS TTL offset"))?;
        let payload_size = query
            .get(class_offset..class_offset + 2)
            .ok_or_else(|| wire_error("EDNS class is out of range"))?;
        let edns_flags = query
            .get(ttl_offset + 2..ttl_offset + 4)
            .ok_or_else(|| wire_error("EDNS flags are out of range"))?;
        let edns_flags = edns_flags
            .try_into()
            .map(u16::from_be_bytes)
            .map_err(|_| wire_error("EDNS flags out of range"))?;
        let do_flag = edns_flags & 0x8000;
        response.push(0);
        response.extend_from_slice(&EDNS_OPT_RTYPE.to_be_bytes());
        response.extend_from_slice(payload_size);
        response.extend_from_slice(&u32::from(do_flag).to_be_bytes());
        response.extend_from_slice(&0_u16.to_be_bytes());
        response
            .get_mut(10..12)
            .ok_or_else(|| wire_error("DNS additional-record count out of range"))?
            .copy_from_slice(&1_u16.to_be_bytes());
    }
    Ok(response)
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) -> Result<()> {
    let dst = bytes
        .get_mut(offset..offset + 2)
        .ok_or_else(|| wire_error("DNS field offset out of range"))?;
    dst.copy_from_slice(&value.to_be_bytes());
    Ok(())
}

fn wire_error(message: &str) -> Error {
    Error::RustError(message.to_string())
}
