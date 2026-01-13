
# ubl-auth

Strict **EdDSA (Ed25519) JWT/JWKS verification** for OIDC-style flows. DID-first: expects `sub` to be a DID (e.g., `did:key:z...` / `did:web:...`).

- Enforces `alg = "EdDSA"`
- Validates `exp` / `nbf` / `iat` with leeway (default 300s)
- Optional `iss` and `aud` checks via `VerifyOptions`
- Built-in JWKS cache (TTL)
- Zero unsafe

## Install
```toml
[dependencies]
ubl-auth = "0.1.1"
```

## Quickstart
```rust
use ubl_auth::{verify_ed25519_jwt_with_jwks, VerifyOptions};

let token = std::env::var("UBL_TOKEN")?;
let jwks_uri = "https://id.ubl.agency/.well-known/jwks.json";
let opts = VerifyOptions::default().with_issuer("https://id.ubl.agency");

let claims = verify_ed25519_jwt_with_jwks(&token, jwks_uri, &opts)?;
assert!(claims.sub.starts_with("did:"));
# Ok::<(), anyhow::Error>(())
```
