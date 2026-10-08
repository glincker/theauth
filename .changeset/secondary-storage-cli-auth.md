---
"@glinr/theauth": minor
"@glinr/theauth-cli": minor
---

Pluggable secondary storage, hardened device auth, CLI login, agent registration tokens.

- New `secondaryStorage` config with memory, database, Cloudflare KV, Redis-compatible and custom adapters, plus per-feature overrides. `kvStore`, `KVStore` and `RateLimitStore` keep working.
- Security: `rateLimit()` no longer trusts `x-forwarded-for` by default. Set `trustedProxyCount` or `trustedHeader`. Behind a proxy without either, all clients share one bucket.
- Security: device authorization takes the approving user from the authenticated session, never from the request body. The approval endpoint rejects cross-origin and non-JSON requests.
- Device codes are stored hashed, user code guessing is limited per user, `slow_down` persists, and a granted code can be exchanged once. The token endpoint returns an `access_token` when a session manager or `issueToken` is configured.
- `rateLimit()` now covers `/mcp/token`, `/mcp/register` and the device endpoints, with an optional per `client_id` key. `theauth.plugins.runRequestHooks()` is new, and `plugins.handleRequest` now runs `onRequest` hooks (they were collected but never invoked).
- CLI: `theauth login`, `logout`, `whoami` and an exported `loginWithDeviceFlow` helper.
- New `agentRegistration()` plugin: one-time, scoped, expiring tokens that let a headless agent register itself.
