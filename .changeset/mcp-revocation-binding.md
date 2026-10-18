---
"@glinr/theauth": major
---

MCP access tokens are now bound to the delegation they came from, and revoking that delegation stops them.

- Tokens minted by RFC 8693 exchange keep the `act` chain and gain a signed `theauth_dlg` claim (`{ v: 1, agt, lnk }`) naming the agents and delegation records behind them. A token never outlives the earliest of its delegation links, its agents and the token it was exchanged from. Exchanged tokens do not get refresh tokens. Tokens for a client bound to an agent carry the agent in the claim too.
- Validation has three freshness modes: `live` (checks the shared denylist and the delegation chain on every request), `cached` (a bounded cache, `maxStalenessMs` defaults to 5 seconds) and `offline` (trusts the signed claim until `exp`). The default is `live` when a database is configured and `offline` otherwise. Signature, audience, issuer, expiry and DPoP are always checked before the claim is read, and a store error fails closed with a 503 from `requireMcpAuth`.
- New shared denylist table `theauth_mcp_revocations` (migration `0007`), which also adds the missing `delegation_chains` indexes. Revoking a delegation (including its cascade), revoking an agent, signing a user out everywhere and `/mcp/revoke` all write to it, so the next request fails on every instance that shares the database. CAEP `session-revoked` events are emitted when the signals module is configured.
- New `POST /mcp/introspect` (RFC 7662). It always checks live state. Only the token's own client or a configured resource server gets the claims or the reason a token is inactive; everyone else gets `{"active":false}`. `McpAuthModule.introspect` is now required.
- `McpBindingRefused` is returned as `invalid_grant` on every grant type, the binding is checked before an authorization code is consumed when the client is bound to an agent, and `expires_in` reports the capped lifetime.
- `jtiDenylist` now defaults to the database store when a database exists.

Limits that stay true: a resource server that validates the JWT offline or caches introspection sees a revocation at token expiry or when its cache expires; a request already past validation finishes; tokens minted before the upgrade carry no binding and age out within the access token lifetime; the HS256 shared secret can forge the claim, so use RS256 or ES256 for resource servers you do not fully trust; nothing pushes a revocation when an agent simply expires, expiry is enforced at check time. See `docs/mcp-revocation.mdx`.
