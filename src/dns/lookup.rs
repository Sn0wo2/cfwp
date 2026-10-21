use std::net::IpAddr;

use domain::base::{Message, MessageBuilder, Name, Rtype};
use domain::rdata::AllRecordData;
use worker::Error;

use super::{DnsError, DnsResult, DnsService, config::AddressFamily};

#[allow(clippy::multiple_inherent_impl)]
impl DnsService {
    pub(crate) async fn resolve(&self, hostname: &str) -> DnsResult<Vec<IpAddr>> {
        if let Ok(address) = hostname.parse::<IpAddr>() {
            return Ok(vec![address]);
        }

        let mut addresses = Vec::new();
        let mut last_error = None;
        let qtypes: &[Rtype] = match self.config.address_family {
            AddressFamily::OnlyV4 => &[Rtype::A],
            AddressFamily::OnlyV6 => &[Rtype::AAAA],
            AddressFamily::None | AddressFamily::PerfV4 | AddressFamily::PerfV6 => {
                &[Rtype::A, Rtype::AAAA]
            }
        };
        for &qtype in qtypes {
            let name = Name::vec_from_str(hostname)
                .map_err(|_| Error::RustError("invalid DNS query name".into()))?;
            let mut id = [0_u8; 2];
            getrandom::fill(&mut id).map_err(|err| {
                Error::RustError(format!("DNS query ID generation failed: {err}"))
            })?;
            let mut builder = MessageBuilder::new_vec();
            builder.header_mut().set_id(u16::from_be_bytes(id));
            builder.header_mut().set_rd(true);
            let mut question = builder.question();
            question
                .push((name, qtype))
                .map_err(|_| Error::RustError("invalid DNS query name".into()))?;
            let query = question.into_message().into_octets();

            let response = match self.exchange(&query, None).await {
                Ok(response) => response,
                Err(err) => {
                    last_error = Some(err);
                    continue;
                }
            };
            let Ok(message) = Message::from_octets(&response) else {
                continue;
            };
            if message.header().rcode() != domain::base::iana::Rcode::NOERROR {
                continue;
            }
            let Ok(answer) = message.answer() else {
                continue;
            };
            for parsed in answer.flatten() {
                if parsed.rtype() != qtype {
                    continue;
                }
                let Ok(Some(record)) = parsed
                    .into_record::<AllRecordData<&[u8], domain::base::name::ParsedName<&[u8]>>>()
                else {
                    continue;
                };
                let address = match record.data() {
                    AllRecordData::A(address) => Some(IpAddr::V4(address.addr())),
                    AllRecordData::Aaaa(address) => Some(IpAddr::V6(address.addr())),
                    _ => None,
                };
                if let Some(address) = address
                    && !addresses.contains(&address)
                {
                    addresses.push(address);
                }
            }
        }

        if addresses.is_empty() {
            return Err(last_error.unwrap_or_else(|| {
                DnsError::Other(Error::RustError(
                    "DNS response contained no usable addresses".into(),
                ))
            }));
        }
        Ok(addresses)
    }
}
