
#![forbid(unsafe_code)]

/// Re-export json_atomic for LLM-first canonical JSON serialization.
pub use json_atomic;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine as _};
use ed25519_dalek::{VerifyingKey, Signature};
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::Value as Json;
use std::{collections::HashMap, time::{SystemTime, UNIX_EPOCH}};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    #[serde(default)]
    pub iss: Option<String>,
    #[serde(default)]
    pub aud: Option<Aud>,
    #[serde(default)]
    pub exp: Option<i64>,
    #[serde(default)]
    pub nbf: Option<i64>,
    #[serde(default)]
    pub iat: Option<i64>,
    #[serde(default)]
    pub jti: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(flatten)]
    pub extra: HashMap<String, Json>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Aud {
    One(String),
    Many(Vec<String>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyOptions {
    pub leeway_secs: i64,
    pub issuer: Option<String>,
    pub audience: Option<String>,
    pub now: Option<i64>,
}
impl Default for VerifyOptions {
    fn default() -> Self {
        Self { leeway_secs: 300, issuer: None, audience: None, now: None }
    }
}
impl VerifyOptions {
    pub fn with_issuer(mut self, iss: &str) -> Self { self.issuer = Some(iss.to_string()); self }
    pub fn with_audience(mut self, aud: &str) -> Self { self.audience = Some(aud.to_string()); self }
    pub fn with_leeway(mut self, secs: i64) -> Self { self.leeway_secs = secs; self }
    pub fn with_now(mut self, now: i64) -> Self { self.now = Some(now); self }
}

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("bad token format")]
    BadFormat,
    #[error("base64 decode failed")]
    Base64,
    #[error("json parse failed")]
    Json,
    #[error("alg not allowed (expected EdDSA)")]
    Alg,
    #[error("missing kid in JWT header")]
    Kid,
    #[error("jwks http error: {0}")]
    JwksHttp(String),
    #[error("jwks parse error")]
    JwksJson,
    #[error("no matching key for kid")]
    NoKey,
    #[error("invalid signature")]
    Signature,
    #[error("claim 'exp' expired")]
    Expired,
    #[error("claim 'nbf' in future")]
    NotYetValid,
    #[error("issuer mismatch")]
    Issuer,
    #[error("audience mismatch")]
    Audience,
    #[error("missing sub")]
    MissingSub,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwk { pub kty:String, #[serde(default)] pub crv:Option<String>, #[serde(default)] pub x:Option<String>, #[serde(default)] pub kid:Option<String> }
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwks { pub keys: Vec<Jwk> }

#[derive(Debug, Clone)]
pub struct JwksCacheEntry { pub jwks: Jwks, pub fetched_at: i64 }
#[derive(Debug)]
pub struct JwksCache { ttl_secs: i64, inner: Mutex<HashMap<String, JwksCacheEntry>> }

static GLOBAL_JWKS: Lazy<JwksCache> = Lazy::new(|| JwksCache::new(300));

impl JwksCache {
    pub fn new(ttl_secs: i64) -> Self { Self { ttl_secs, inner: Mutex::new(HashMap::new()) } }
    pub fn put(&self, uri: &str, jwks: Jwks) {
        let mut m = self.inner.lock();
        m.insert(uri.to_string(), JwksCacheEntry{ jwks, fetched_at: now_ts() });
    }
    pub fn get_fresh(&self, uri: &str) -> Option<Jwks> {
        let m = self.inner.lock();
        if let Some(entry) = m.get(uri) {
            if now_ts() - entry.fetched_at <= self.ttl_secs {
                return Some(entry.jwks.clone());
            }
        }
        None
    }
}

pub fn verify_ed25519_jwt_with_jwks(token: &str, jwks_uri: &str, opts: &VerifyOptions) -> Result<Claims, VerifyError> {
    verify_ed25519_jwt_with_cache(token, jwks_uri, &GLOBAL_JWKS, opts)
}

pub fn verify_ed25519_jwt_with_cache(token: &str, jwks_uri: &str, cache: &JwksCache, opts: &VerifyOptions) -> Result<Claims, VerifyError> {
    let (header, payload, sig, signing_input) = split_and_decode(token)?;

    let alg = header.get("alg").and_then(|v| v.as_str()).ok_or(VerifyError::Alg)?;
    if alg != "EdDSA" { return Err(VerifyError::Alg); }
    let kid = header.get("kid").and_then(|v| v.as_str()).ok_or(VerifyError::Kid)?;

    let jwks = if let Some(j) = cache.get_fresh(jwks_uri) { j } else {
        let fetched = fetch_jwks(jwks_uri)?;
        cache.put(jwks_uri, fetched.clone());
        fetched
    };
    let vk = key_by_kid(&jwks, kid).ok_or(VerifyError::NoKey)?;

    vk.verify_strict(signing_input.as_bytes(), &sig).map_err(|_| VerifyError::Signature)?;

    let claims: Claims = serde_json::from_value(payload).map_err(|_| VerifyError::Json)?;
    check_claims(&claims, opts)?;
    Ok(claims)
}

fn split_and_decode(token: &str) -> Result<(Json, Json, Signature, String), VerifyError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 { return Err(VerifyError::BadFormat); }
    let header_json = String::from_utf8(B64URL.decode(parts[0].as_bytes()).map_err(|_| VerifyError::Base64)?).map_err(|_| VerifyError::Base64)?;
    let payload_json = String::from_utf8(B64URL.decode(parts[1].as_bytes()).map_err(|_| VerifyError::Base64)?).map_err(|_| VerifyError::Base64)?;
    let sig_bytes = B64URL.decode(parts[2].as_bytes()).map_err(|_| VerifyError::Base64)?;
    let sig = Signature::from_bytes(sig_bytes[..].try_into().map_err(|_| VerifyError::Signature)?);
    let header: Json = serde_json::from_str(&header_json).map_err(|_| VerifyError::Json)?;
    let payload: Json = serde_json::from_str(&payload_json).map_err(|_| VerifyError::Json)?;
    Ok((header, payload, sig, format!("{}.{}", parts[0], parts[1])))
}

fn fetch_jwks(uri: &str) -> Result<Jwks, VerifyError> {
    let resp = ureq::get(uri).call().map_err(|e| VerifyError::JwksHttp(e.to_string()))?;
    let body = resp.into_string().map_err(|e| VerifyError::JwksHttp(e.to_string()))?;
    serde_json::from_str(&body).map_err(|_| VerifyError::JwksJson)
}

fn key_by_kid(jwks: &Jwks, kid: &str) -> Option<VerifyingKey> {
    for k in &jwks.keys {
        if k.kty != "OKP" { continue; }
        if k.crv.as_deref() != Some("Ed25519") { continue; }
        let k_kid = k.kid.as_deref().unwrap_or_default();
        if k_kid == kid || k_kid.is_empty() {
            if let Some(x) = &k.x {
                if let Ok(bytes) = B64URL.decode(x.as_bytes()) {
                    if let Ok(vk) = VerifyingKey::from_bytes(bytes[..].try_into().ok()?) {
                        return Some(vk);
                    }
                }
            }
        }
    }
    None
}

pub fn now_ts() -> i64 {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
    now
}

fn check_claims(c: &Claims, opts: &VerifyOptions) -> Result<(), VerifyError> {
    let now = opts.now.unwrap_or_else(now_ts);
    if c.sub.is_empty() { return Err(VerifyError::MissingSub); }
    if let Some(exp) = c.exp {
        if now > exp + opts.leeway_secs { return Err(VerifyError::Expired); }
    }
    if let Some(nbf) = c.nbf {
        if now + opts.leeway_secs < nbf { return Err(VerifyError::NotYetValid); }
    }
    if let Some(iat) = c.iat {
        if iat > now + opts.leeway_secs { return Err(VerifyError::NotYetValid); }
    }
    if let Some(ref iss) = opts.issuer {
        if c.iss.as_deref() != Some(iss) { return Err(VerifyError::Issuer); }
    }
    if let Some(ref aud) = opts.audience {
        match &c.aud {
            None => return Err(VerifyError::Audience),
            Some(Aud::One(s)) if s != aud => return Err(VerifyError::Audience),
            Some(Aud::Many(v)) if !v.iter().any(|x| x == aud) => return Err(VerifyError::Audience),
            _ => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{SeedableRng, rngs::StdRng};
    use ed25519_dalek::{SigningKey, Signer};
    use serde_json::json;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
    use json_atomic::canonize;

    #[test]
    fn roundtrip_sign_and_verify_with_cache() {
        let mut rng = StdRng::seed_from_u64(42);
        let sk = SigningKey::generate(&mut rng);
        let vk = sk.verifying_key();
        let x = B64URL.encode(vk.to_bytes());

        let cache = JwksCache::new(3600);
        cache.put("mem://jwks", Jwks{ keys: vec![ Jwk{ kty:"OKP".into(), crv:Some("Ed25519".into()), x:Some(x), kid:Some("test".into()) } ]});

        let header = json!({"alg":"EdDSA","kid":"test","typ":"JWT"});
        let now = now_ts();
        let payload = json!({
            "sub":"did:key:zTest",
            "iss":"https://id.ubl.agency",
            "aud":"demo",
            "iat": now,
            "nbf": now - 5,
            "exp": now + 3600
        });
        let hdr = B64URL.encode(canonize(&header).unwrap());
        let pld = B64URL.encode(canonize(&payload).unwrap());
        let msg = format!("{}.{}", hdr, pld);
        let sig = sk.sign(msg.as_bytes());
        let jwt = format!("{}.{}", msg, B64URL.encode(sig.to_bytes()));

        let opts = VerifyOptions::default().with_issuer("https://id.ubl.agency").with_audience("demo");
        let claims = verify_ed25519_jwt_with_cache(&jwt, "mem://jwks", &cache, &opts).expect("verify");
        assert_eq!(claims.sub, "did:key:zTest");
    }
}
