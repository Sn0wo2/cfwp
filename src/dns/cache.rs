use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use worker::{Cache, Error, Headers, Response};

use super::{
    DnsResult,
    config::CacheConfig,
    util::{DNS_MESSAGE_TYPE, read_body},
    wire::{age, parse_message, validate_response},
};

pub(super) struct DnsCache {
    pub(super) prefix: String,
    pub(super) config: CacheConfig,
}

impl DnsCache {
    pub(super) fn key(&self, query: &[u8]) -> DnsResult<String> {
        let query = query
            .get(2..)
            .ok_or_else(|| Error::RustError("DNS query header out of range".into()))?;
        Ok(format!(
            "{}{}",
            self.prefix,
            URL_SAFE_NO_PAD.encode(Sha256::digest(query))
        ))
    }

    pub(super) async fn load(
        &self,
        key: &str,
        query: &[u8],
        max_message_bytes: usize,
    ) -> DnsResult<Option<Vec<u8>>> {
        let Some(mut cached) = Cache::open("cfwp-dns".into()).await.get(key, false).await? else {
            return Ok(None);
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
        let mut bytes = read_body(cached.stream()?, max_message_bytes).await?;
        if bytes.len() < 12 {
            return Ok(None);
        }
        bytes
            .get_mut(..2)
            .ok_or_else(|| Error::RustError("DNS response ID out of range".into()))?
            .copy_from_slice(
                query
                    .get(..2)
                    .ok_or_else(|| Error::RustError("DNS query ID out of range".into()))?,
            );
        validate_response(query, &bytes)?;
        age(&mut bytes, elapsed)?;
        Ok(Some(bytes))
    }

    pub(super) async fn store(&self, key: &str, response: &[u8]) -> DnsResult<()> {
        if response.len() > self.config.max_message_bytes {
            return Ok(());
        }
        let parsed = parse_message(response)?;
        let Some(ttl) = parsed
            .cacheable_ttl()
            .map(|ttl| ttl.min(self.config.max_ttl))
            .filter(|ttl| *ttl != 0)
        else {
            return Ok(());
        };
        let headers = Headers::new();
        headers.set("content-type", DNS_MESSAGE_TYPE)?;
        headers.set("cache-control", &format!("public, max-age={ttl}"))?;
        headers.set("x-cfwp-stored-at", &js_sys::Date::now().to_string())?;
        headers.set("x-cfwp-ttl", &ttl.to_string())?;
        Cache::open("cfwp-dns".into())
            .await
            .put(
                key,
                Response::from_bytes(response.to_vec())?.with_headers(headers),
            )
            .await?;
        Ok(())
    }
}
