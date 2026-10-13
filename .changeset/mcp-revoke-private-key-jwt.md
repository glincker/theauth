---
"@glinr/theauth": minor
---

`/mcp/revoke` accepts `private_key_jwt` client authentication (`client_assertion` and `client_assertion_type`), reusing the token endpoint verifier. The assertion `aud` must be the revocation endpoint or the issuer, each `jti` is single use across the token and revocation endpoints, and an assertion cannot be combined with a client secret. `client_secret_basic`, `client_secret_post` and public clients are unchanged. Discovery now lists `private_key_jwt` and the signing algorithms under `revocation_endpoint_auth_methods_supported` and `revocation_endpoint_auth_signing_alg_values_supported`.
