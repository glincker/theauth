---
"@glinr/theauth": major
"@glinr/theauth-express": patch
"@glinr/theauth-nestjs": patch
"@glinr/theauth-nextjs-auth": minor
---

Security hardening from the HTTP handler review, part B.

Fixes that also affect PUBLISHED versions (verified against origin/main):

- nextjs-auth: the refresh cookie now uses the `__Host-` prefix (`__Host-{prefix}-refresh-token`, Secure, Path=/, no Domain) whenever `secure` is on, not only in production. Before, a sibling subdomain could set the unprefixed cookie and sign a visitor in as the attacker (login CSRF). `secure: false` (plain http localhost development) is the only way back to the unprefixed name. Existing refresh cookies under the old name are ignored and cleared, so each user signs in once more after the upgrade.
- Adapter admission (`adapter-admit`): with an unknown client IP, requests no longer share one global `unknown` bucket or get a bucket per raw `Cookie` or `Authorization` value (a random cookie bypassed the limit). They now fall into three fixed buckets (anonymous, cookie, authorization) and a one-time warning is logged. Limits are only per client with `trustedProxy` or `rateLimit.key`; see `docs/rate-limiting.mdx`.
- Redirect chain: `createRedirectChain` kept `currentState` in a shared closure, so one user's origin path and query (for example a share token) could land in another user's cookie. State now comes only from the request. BREAKING: `push(path, options)` is now `push(request, path, options)`, and it reads the chain from that request's cookie.

Fixes in unreleased 2.0 work only (these code paths are not on main):

- HTTP handler: `readJsonBody`, `/mcp/register` and `/mcp/token` enforce `maxBodyBytes` while streaming. A Content-Length over the cap is refused up front and the reader is cancelled once the running total passes it (413). Before, a chunked body was buffered in full first.
- Login lockout: `check()` now reserves an attempt slot with an atomic increment before the password is verified, and a correct password refunds it. 200 parallel guesses with `maxFailures: 10` now perform about 10 password checks instead of 200. A lock and its escalation strike are set once per burst.
- MCP routes return a fixed `server_error` description on 500 (register, authorize, token, jwks). The original error goes to the configured logger.

Express and NestJS adapters (also on main): the per-mount handler cache is keyed by the lowercased mount and capped at 32 mounts, so request-chosen spellings of `req.baseUrl` no longer build a handler (guard, admission, compiled routes) each.
