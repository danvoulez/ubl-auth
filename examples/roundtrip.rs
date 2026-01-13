
use ubl_auth::{verify_ed25519_jwt_with_cache, VerifyOptions, JwksCache, Jwk, Jwks};
use ed25519_dalek::{SigningKey, Signer};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine as _};
use serde_json::json;
use rand::{SeedableRng, rngs::StdRng};

fn main() -> anyhow::Result<()> {
    let mut rng = StdRng::seed_from_u64(7);
    let sk = SigningKey::generate(&mut rng);
    let vk = sk.verifying_key();

    let x = B64URL.encode(vk.to_bytes());
    let cache = JwksCache::new(3600);
    cache.put("mem://jwks", Jwks{ keys: vec![ Jwk{ kty:"OKP".into(), crv:Some("Ed25519".into()), x:Some(x), kid:Some("demo".into()) } ]});

    let now = ubl_auth::now_ts();
    let header = json!({"alg":"EdDSA","kid":"demo","typ":"JWT"});
    let payload = json!({ "sub":"did:key:zDemo", "iss":"issuer", "aud":"example", "iat":now, "nbf":now, "exp": now+600 });
    let hdr = B64URL.encode(serde_json::to_string(&header)?);
    let pld = B64URL.encode(serde_json::to_string(&payload)?);
    let msg = format!("{}.{}", hdr, pld);
    let sig = sk.sign(msg.as_bytes());
    let jwt = format!("{}.{}", msg, B64URL.encode(sig.to_bytes()));

    let opts = VerifyOptions::default().with_issuer("issuer").with_audience("example");
    let claims = verify_ed25519_jwt_with_cache(&jwt, "mem://jwks", &cache, &opts)?;
    println!("verified sub = {}", claims.sub);
    Ok(())
}
