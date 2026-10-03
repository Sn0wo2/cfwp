use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::{AesGcmParams, CryptoKey, SubtleCrypto};
use worker::{Error, Result};

fn subtle() -> Result<SubtleCrypto> {
    js_sys::Reflect::get(&js_sys::global(), &"crypto".into())
        .map_err(|_| Error::RustError("WebCrypto is unavailable".into()))
        .map(|crypto| crypto.unchecked_into::<web_sys::Crypto>().subtle())
}

fn js_error(context: &str) -> impl Fn(wasm_bindgen::JsValue) -> Error + '_ {
    move |err| Error::RustError(format!("{context}: {err:?}"))
}

pub(super) async fn import_aes_gcm_key(key: &[u8]) -> Result<CryptoKey> {
    let subtle = subtle()?;
    let usages = js_sys::Array::of2(&"encrypt".into(), &"decrypt".into());
    let promise = subtle
        .import_key_with_str(
            "raw",
            &js_sys::Uint8Array::from(key),
            "AES-GCM",
            false,
            &usages.into(),
        )
        .map_err(js_error("AES-GCM key import failed"))?;
    JsFuture::from(promise)
        .await
        .map(JsCast::unchecked_into::<CryptoKey>)
        .map_err(js_error("AES-GCM key import failed"))
}

pub(super) async fn aes_gcm_encrypt(
    key: &CryptoKey,
    nonce: &[u8],
    aad: Option<&[u8]>,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    aes_gcm(key, nonce, aad, plaintext, true).await
}

pub(super) async fn aes_gcm_decrypt(
    key: &CryptoKey,
    nonce: &[u8],
    aad: Option<&[u8]>,
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    aes_gcm(key, nonce, aad, ciphertext, false).await
}

async fn aes_gcm(
    key: &CryptoKey,
    nonce: &[u8],
    aad: Option<&[u8]>,
    data: &[u8],
    encrypt: bool,
) -> Result<Vec<u8>> {
    let subtle = subtle()?;
    let params = AesGcmParams::new("AES-GCM", &js_sys::Uint8Array::from(nonce));
    if let Some(aad) = aad {
        params.set_additional_data(&js_sys::Uint8Array::from(aad));
    }
    let promise = if encrypt {
        subtle.encrypt_with_object_and_u8_array(&params, key, data)
    } else {
        subtle.decrypt_with_object_and_u8_array(&params, key, data)
    }
    .map_err(js_error("WebCrypto AES-GCM call failed"))?;
    let result = JsFuture::from(promise)
        .await
        .map_err(js_error("WebCrypto AES-GCM operation failed"))?;
    Ok(js_sys::Uint8Array::new(&result).to_vec())
}
