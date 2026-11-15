use std::{net::IpAddr, time::Duration};

use domain::base::iana::{Opcode, OptRcode, Rtype};
use domain::base::message::Section;
use domain::base::opt::{ClientSubnet, ComposeOptData, UnknownOptData};
use domain::base::{Message, ParsedName};
use domain::rdata::AllRecordData;
use futures_util::{
    FutureExt,
    future::{
        Either::{Left, Right},
        select,
    },
};
use worker::{Delay, Error, Result};

use super::{DnsError, DnsResult, DnsService, config::AddressFamily};

const EDNS_OPT_RTYPE: u16 = 41;

#[derive(Clone)]
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

impl ParsedMessage {
    pub(super) fn cacheable_ttl(&self) -> Option<u32> {
        if !self.qr
            || self.truncated
            || self.signed
            || self.has_cookie
            || (self.rcode != OptRcode::NOERROR && self.rcode != OptRcode::NXDOMAIN)
        {
            return None;
        }
        if self.answer_count > 0 && self.rcode == OptRcode::NOERROR {
            self.records
                .iter()
                .filter(|record| record.rtype != Rtype::OPT)
                .map(|record| record.ttl)
                .min()
        } else {
            let negative_ttl = self
                .records
                .iter()
                .filter(|record| record.section == Section::Authority)
                .filter_map(|record| record.soa_minimum.map(|minimum| record.ttl.min(minimum)))
                .min();
            let record_ttl = self
                .records
                .iter()
                .filter(|record| record.rtype != Rtype::OPT)
                .map(|record| record.ttl)
                .min();
            negative_ttl.map(|ttl| ttl.min(record_ttl.unwrap_or(ttl)))
        }
    }
}

#[allow(clippy::multiple_inherent_impl)]
impl DnsService {
    pub(crate) fn prepare(&self, payload: &[u8], client_ip: Option<IpAddr>) -> DnsResult<Prepared> {
        if payload.len() > self.config.max_message_bytes {
            return Err(DnsError::TooLarge);
        }

        let parsed = parse_message(payload)?;
        if parsed.qr {
            return Err(Error::RustError("expected a DNS query".into()).into());
        }
        if parsed.opcode != Opcode::QUERY {
            return Err(Error::RustError("only standard DNS queries are supported".into()).into());
        }
        if parsed.question_count == 0 {
            return Err(Error::RustError("DNS query has no question".into()).into());
        }

        let policy = self.config.address_family;
        let blocked = match policy {
            AddressFamily::OnlyV4 => parsed.question_types.contains(&Rtype::AAAA),
            AddressFamily::OnlyV6 => parsed.question_types.contains(&Rtype::A),
            _ => false,
        };
        if blocked {
            if parsed.question_count != 1 {
                return Err(Error::RustError(
                    "address-family filtering requires a single-question DNS query".into(),
                )
                .into());
            }
            if parsed.signed {
                return Err(Error::RustError(
                    "cannot synthesize an address-family response for a signed DNS query".into(),
                )
                .into());
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
                return Err(Error::RustError(
                    "address-family preference requires a single-question DNS query".into(),
                )
                .into());
            }
            if parsed.signed {
                return Err(Error::RustError(
                    "cannot rewrite a signed DNS query for address-family preference".into(),
                )
                .into());
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
                .map_err(|_| Error::RustError("failed to compose EDNS client subnet".into()))?;
            let mut option = Vec::with_capacity(4 + data.len());
            option.extend_from_slice(&8_u16.to_be_bytes());
            option.extend_from_slice(
                &u16::try_from(data.len())
                    .map_err(|_| Error::RustError("EDNS client subnet is too large".into()))?
                    .to_be_bytes(),
            );
            option.extend_from_slice(&data);

            injected = 'ecs: {
                if let Some(opt) = parsed.opt {
                    if opt.end != bytes.len() {
                        break 'ecs false;
                    }
                    let Some(new_rdlen) = opt.rdlen.checked_add(option.len()) else {
                        break 'ecs false;
                    };
                    if new_rdlen > usize::from(u16::MAX)
                        || bytes.len() + option.len() > usize::from(u16::MAX)
                    {
                        break 'ecs false;
                    }
                    let Ok(new_rdlen) = u16::try_from(new_rdlen) else {
                        break 'ecs false;
                    };
                    bytes.extend_from_slice(&option);
                    bytes
                        .get_mut(opt.rdlen_offset..opt.rdlen_offset + 2)
                        .ok_or_else(|| {
                            Error::RustError("EDNS resource-data length out of range".into())
                        })?
                        .copy_from_slice(&new_rdlen.to_be_bytes());
                } else {
                    let arcount = bytes
                        .get(10..12)
                        .and_then(|bytes| bytes.try_into().ok())
                        .map(u16::from_be_bytes)
                        .ok_or_else(|| {
                            Error::RustError("DNS additional-record count out of range".into())
                        })?;
                    if arcount == u16::MAX
                        || bytes.len() + 11 + option.len() > usize::from(u16::MAX)
                        || option.len() > usize::from(u16::MAX)
                    {
                        break 'ecs false;
                    }
                    let Ok(rdlen) = u16::try_from(option.len()) else {
                        break 'ecs false;
                    };
                    bytes.push(0);
                    bytes.extend_from_slice(&EDNS_OPT_RTYPE.to_be_bytes());
                    bytes.extend_from_slice(&1232_u16.to_be_bytes());
                    bytes.extend_from_slice(&0_u32.to_be_bytes());
                    bytes.extend_from_slice(&rdlen.to_be_bytes());
                    bytes.extend_from_slice(&option);
                    bytes
                        .get_mut(10..12)
                        .ok_or_else(|| {
                            Error::RustError("DNS additional-record count out of range".into())
                        })?
                        .copy_from_slice(&(arcount + 1).to_be_bytes());
                }
                true
            };
            cacheable &= injected;
        }

        if bytes.len() > self.config.max_message_bytes {
            return Err(Error::RustError("DNS query too large after ECS injection".into()).into());
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

    pub(crate) async fn exchange_prepared(&self, prepared: Prepared) -> DnsResult<Vec<u8>> {
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
                .ok_or_else(|| Error::RustError("missing DNS question type offset".into()))?;
            let mut probe = prepared.clone();
            write_u16(&mut probe.bytes, offset, u16::from(preferred_type))?;
            if let Some(original) = &mut probe.original {
                write_u16(original, offset, u16::from(preferred_type))?;
            }
            probe.question_type = Some(preferred_type);
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
    ) -> DnsResult<Vec<u8>> {
        let fallback_query = fallback.bytes.clone();
        let question_end = fallback.question_end;
        let timeout_ms = self.config.request_timeout_ms;
        let timer = Delay::from(Duration::from_millis(u64::from(timeout_ms))).fuse();
        futures_util::pin_mut!(timer);
        let fallback = Box::pin(self.exchange_query(fallback));
        let probe = Box::pin(self.exchange_query(probe));

        let (fallback, probe_response) = match select(fallback, probe).await {
            Left((fallback_result, probe)) => (
                Left(fallback_result),
                match select(probe, timer.as_mut()).await {
                    Left((result, _)) => result.ok(),
                    Right(_) => None,
                },
            ),
            Right((probe_result, fallback)) => (Right(fallback), probe_result.ok()),
        };
        if let Some(response) = probe_response {
            let parsed = parse_message(&response)?;
            if parsed.rcode == OptRcode::NOERROR
                && parsed.records.iter().any(|record| {
                    record.section == Section::Answer && record.rtype == preferred_type
                })
            {
                return Ok(make_nodata_response(&fallback_query, question_end)?);
            }
        }
        match fallback {
            Left(fallback_result) => fallback_result,
            Right(fallback) => match select(fallback, timer).await {
                Left((fallback_result, _)) => fallback_result,
                Right(((), _)) => Err(DnsError::Timeout(timeout_ms)),
            },
        }
    }

    async fn exchange_query(&self, prepared: Prepared) -> DnsResult<Vec<u8>> {
        let cache_key = self
            .cache
            .as_ref()
            .filter(|_| prepared.cacheable)
            .map(|cache| cache.key(&prepared.bytes).map(|key| (cache, key)))
            .transpose()?;
        let mut response = None;
        if let Some((cache, key)) = &cache_key {
            match cache
                .load(key, &prepared.bytes, self.config.max_message_bytes)
                .await
            {
                Ok(cached) => response = cached,
                Err(err) => tracing::info!("DNS cache read failed: {err}"),
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
                    && let Some((cache, key)) = cache_key
                    && let Err(err) = cache.store(&key, &response).await
                {
                    tracing::info!("DNS cache write failed: {err}");
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
                && !parsed.ecs_ranges.is_empty()
                && let Some(opt) = parsed.opt
            {
                if opt.end == response.len() {
                    let removed = parsed
                        .ecs_ranges
                        .iter()
                        .map(|(start, end)| end - start)
                        .sum::<usize>();
                    for (start, end) in parsed.ecs_ranges.into_iter().rev() {
                        response.drain(start..end);
                    }
                    write_u16(
                        &mut response,
                        opt.rdlen_offset,
                        opt.rdlen
                            .checked_sub(removed)
                            .ok_or_else(|| Error::RustError("invalid ECS option length".into()))?
                            as u16,
                    )?;
                } else {
                    for (start, end) in parsed.ecs_ranges {
                        write_u16(&mut response, start, 12_u16)?;
                        response
                            .get_mut(start + 4..end)
                            .ok_or_else(|| {
                                Error::RustError("EDNS padding range out of bounds".into())
                            })?
                            .fill(0);
                    }
                }
                parse_message(&response)?;
            }
        }
        Ok(response)
    }
}

pub(super) fn validate_response(query: &[u8], response: &[u8]) -> Result<()> {
    let query_message = Message::from_slice(query)
        .map_err(|_| Error::RustError("malformed DNS query header".into()))?;
    let response_info = parse_message(response)?;
    if !response_info.qr || response_info.opcode != query_message.header().opcode() {
        return Err(Error::RustError(
            "DNS response header does not match query".into(),
        ));
    }

    let response_message = Message::from_slice(response)
        .map_err(|_| Error::RustError("malformed DNS response header".into()))?;
    if !response_message.is_answer(query_message) {
        return Err(Error::RustError("DNS response does not match query".into()));
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
            .ok_or_else(|| Error::RustError("DNS field offset out of range".into()))?;
        dst.copy_from_slice(&record.ttl.saturating_sub(seconds).to_be_bytes());
    }
    Ok(())
}

pub(super) fn parse_message(payload: &[u8]) -> Result<ParsedMessage> {
    if payload.len() > u16::MAX as usize {
        return Err(Error::RustError("DNS message is too large".into()));
    }
    let message = Message::from_slice(payload)
        .map_err(|_| Error::RustError("DNS message is shorter than its header".into()))?;

    let mut questions = message.question();
    let mut question_types = Vec::new();
    let mut question_type_offsets = Vec::new();
    while let Some(question) = questions.next() {
        let question = question.map_err(|_| Error::RustError("malformed DNS question".into()))?;
        let offset = questions
            .pos()
            .checked_sub(4)
            .ok_or_else(|| Error::RustError("invalid DNS question offset".into()))?;
        question_types.push(question.qtype());
        question_type_offsets.push(offset);
    }
    let question_end = questions.pos();

    let counts = message.header_counts();
    let mut records = Vec::new();
    let mut opt = None;
    let mut opt_count = 0;
    let mut ext_rcode = 0;
    let mut has_ecs = false;
    let mut ecs_ranges = Vec::new();
    let mut has_cookie = false;
    let mut signed = false;
    let mut section = message
        .answer()
        .map_err(|_| Error::RustError("malformed DNS answer section".into()))?;

    for section_kind in [Section::Answer, Section::Authority, Section::Additional] {
        while let Some(record) = section.next() {
            let record =
                record.map_err(|_| Error::RustError("malformed DNS resource record".into()))?;
            let end = section.pos();
            let rtype = record.rtype();
            let rdlen = usize::from(record.rdlen());
            let rdata_start = end
                .checked_sub(rdlen)
                .ok_or_else(|| Error::RustError("invalid DNS resource-data length".into()))?;
            let rdlen_offset = rdata_start
                .checked_sub(2)
                .ok_or_else(|| Error::RustError("invalid DNS resource-data offset".into()))?;
            let ttl_offset = rdata_start
                .checked_sub(6)
                .ok_or_else(|| Error::RustError("invalid DNS TTL offset".into()))?;
            let ttl = record.ttl().as_secs();
            let owner_is_root = record.owner().is_root();

            let parsed_rr = record
                .to_any_record::<AllRecordData<&[u8], ParsedName<&[u8]>>>()
                .map_err(|_| Error::RustError("malformed DNS resource data".into()))?;
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
                    return Err(Error::RustError("invalid EDNS OPT record".into()));
                }
                opt_count += 1;
                if opt_count > 1 {
                    return Err(Error::RustError("multiple EDNS OPT records".into()));
                }
                ext_rcode = (ttl >> 24) as u8;
                let AllRecordData::Opt(options) = rdata else {
                    return Err(Error::RustError("malformed EDNS OPT data".into()));
                };
                let mut option_pos = rdata_start;
                for option in options.iter::<UnknownOptData<&[u8]>>() {
                    let option =
                        option.map_err(|_| Error::RustError("malformed EDNS option".into()))?;
                    let option_end = option_pos + 4 + option.as_slice().len();
                    match u16::from(option.code()) {
                        8 => {
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
                let AllRecordData::Soa(soa) = rdata else {
                    return Err(Error::RustError("malformed SOA resource data".into()));
                };
                soa_minimum = Some(soa.minimum().as_secs());
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
                return Err(Error::RustError("trailing bytes after DNS sections".into()));
            }
        } else {
            section = section
                .next_section()
                .map_err(|_| Error::RustError("malformed DNS record section".into()))?
                .ok_or_else(|| Error::RustError("missing DNS record section".into()))?;
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

fn make_nodata_response(query: &[u8], question_end: usize) -> Result<Vec<u8>> {
    if query.len() < 12 || !(12..=query.len()).contains(&question_end) {
        return Err(Error::RustError("invalid DNS question bounds".into()));
    }
    let parsed = parse_message(query)?;
    let mut response = query
        .get(..question_end)
        .ok_or_else(|| Error::RustError("invalid DNS question bounds".into()))?
        .to_vec();
    let query_flags = query
        .get(2..4)
        .and_then(|flags| flags.try_into().ok())
        .map(u16::from_be_bytes)
        .ok_or_else(|| Error::RustError("DNS query flags out of range".into()))?;
    let response_flags = (query_flags & 0x7800) | (query_flags & 0x0100) | 0x8080;
    response
        .get_mut(2..4)
        .ok_or_else(|| Error::RustError("DNS response flags out of range".into()))?
        .copy_from_slice(&response_flags.to_be_bytes());
    response
        .get_mut(6..12)
        .ok_or_else(|| Error::RustError("DNS response counts out of range".into()))?
        .fill(0);
    if let Some(opt) = parsed.opt {
        let class_offset = opt
            .rdlen_offset
            .checked_sub(6)
            .ok_or_else(|| Error::RustError("invalid EDNS class offset".into()))?;
        let ttl_offset = opt
            .rdlen_offset
            .checked_sub(4)
            .ok_or_else(|| Error::RustError("invalid EDNS TTL offset".into()))?;
        let payload_size = query
            .get(class_offset..class_offset + 2)
            .ok_or_else(|| Error::RustError("EDNS class is out of range".into()))?;
        let edns_flags = query
            .get(ttl_offset + 2..ttl_offset + 4)
            .ok_or_else(|| Error::RustError("EDNS flags are out of range".into()))?;
        let edns_flags = edns_flags
            .try_into()
            .map(u16::from_be_bytes)
            .map_err(|_| Error::RustError("EDNS flags out of range".into()))?;
        let do_flag = edns_flags & 0x8000;
        response.push(0);
        response.extend_from_slice(&EDNS_OPT_RTYPE.to_be_bytes());
        response.extend_from_slice(payload_size);
        response.extend_from_slice(&u32::from(do_flag).to_be_bytes());
        response.extend_from_slice(&0_u16.to_be_bytes());
        response
            .get_mut(10..12)
            .ok_or_else(|| Error::RustError("DNS additional-record count out of range".into()))?
            .copy_from_slice(&1_u16.to_be_bytes());
    }
    Ok(response)
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) -> Result<()> {
    let dst = bytes
        .get_mut(offset..offset + 2)
        .ok_or_else(|| Error::RustError("DNS field offset out of range".into()))?;
    dst.copy_from_slice(&value.to_be_bytes());
    Ok(())
}
