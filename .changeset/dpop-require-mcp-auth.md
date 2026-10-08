---
"@glinr/theauth": minor
---

Add opt-in DPoP (RFC 9449) and a `requireMcpAuth` resource wrapper for MCP.

- New `dpop` option on the MCP config. The token endpoint verifies proofs, issues `cnf.jkt`-bound tokens with `token_type: "DPoP"`, supports server nonces (`use_dpop_nonce`) and keeps a `jti` replay cache on `SecondaryStorage`. Refresh tokens stay bound to the original key. Metadata advertises `dpop_signing_alg_values_supported`.
- New `requireMcpAuth(ctx, handler, options)` and `mcp.requireMcpAuth(...)`: verifies Bearer or DPoP tokens, audience and scopes, returns RFC 6750, RFC 9449 and RFC 9728 challenges, and passes the handler a principal (user, agent, delegation chain).
- Security: a DPoP-bound token is now rejected when presented as a bearer token, including through `validateToken`, `middleware`, `withMcpAuth` and `requireScopes`.
- `McpAccessToken.tokenType` and `McpTokenResponse.token_type` widen to `"Bearer" | "DPoP"`. Persist the new `dpopJkt` field in custom token stores.
- Hono and Express adapters forward the `DPoP-Nonce` header from the token endpoint.
