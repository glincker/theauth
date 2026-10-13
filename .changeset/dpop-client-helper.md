---
"@glinr/theauth-client": minor
---

Add `createDPoPProver` and `createDPoPClient`: an edge safe RFC 9449 helper that builds ES256 DPoP proofs (htm, normalized htu, iat, jti, ath), caches the server nonce per origin, retries once on `use_dpop_nonce`, and exposes a `fetch` wrapper and the JWK thumbprint.
