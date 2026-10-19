# @glinr/theauth-express

## 6.0.0

### Major Changes

- a561306: Rebuilt on the core HTTP handler (`createTheAuthHandler` from `@glinr/theauth/http`) using `toWebRequest` and `sendWebResponse`. `theAuthExpress` is now thin glue and serves every route, including `POST /mcp/revoke`, `GET /mcp/jwks` and `POST /explain`.

  Upgrade notes:

  - `TheAuthExpressOptions` is now the core `TheAuthHandlerOptions` (`mcp`, `basePath`, `routes`, `maxBodyBytes` and the existing security options). `basePath` defaults to where you mount the router. Bodies over `maxBodyBytes` (1 MiB) get 413.
  - Removed the deprecated `authExpress` alias. Use `theAuthExpress`.
  - `POST /authorize/token` answers 401 for `invalid_token`, `agent_not_found`, `agent_revoked` and `agent_expired`, and 403 for every other denial. A known path with the wrong method answers 405.
  - `requireScope` now uses the core `requireAgent` decision-code mapping. Denial bodies are `{ error: { code, message } }` with the decision code (for example `no_permission`) instead of `UNAUTHORIZED` or `FORBIDDEN`. `getAgent(res)` no longer returns the token.
  - The client IP now comes from the socket peer address, or from forwarded headers when `trustedProxy` is set.

### Patch Changes

- a561306: Security hardening from the HTTP handler review, part B.

  Fixes that also affect PUBLISHED versions (verified against origin/main):

  - nextjs-auth: the refresh cookie now uses the `__Host-` prefix (`__Host-{prefix}-refresh-token`, Secure, Path=/, no Domain) whenever `secure` is on, not only in production. Before, a sibling subdomain could set the unprefixed cookie and sign a visitor in as the attacker (login CSRF). `secure: false` (plain http localhost development) is the only way back to the unprefixed name. Existing refresh cookies under the old name are ignored and cleared, so each user signs in once more after the upgrade.
  - Adapter admission (`adapter-admit`): with an unknown client IP, requests no longer share one global `unknown` bucket or get a bucket per raw `Cookie` or `Authorization` value (a random cookie bypassed the limit). They now fall into three fixed buckets (anonymous, cookie, authorization) and a one-time warning is logged. Limits are only per client with `trustedProxy` or `rateLimit.key`; see `docs/rate-limiting.mdx`.
  - Redirect chain: `createRedirectChain` kept `currentState` in a shared closure, so one user's origin path and query (for example a share token) could land in another user's cookie. State now comes only from the request. BREAKING: `push(path, options)` is now `push(request, path, options)`, and it reads the chain from that request's cookie.

  Fixes in unreleased 2.0 work only (these code paths are not on main):

  - HTTP handler: `readJsonBody`, `/mcp/register` and `/mcp/token` enforce `maxBodyBytes` while streaming. A Content-Length over the cap is refused up front and the reader is cancelled once the running total passes it (413). Before, a chunked body was buffered in full first.
  - Login lockout: `check()` now reserves an attempt slot with an atomic increment before the password is verified, and a correct password refunds it. 200 parallel guesses with `maxFailures: 10` now perform about 10 password checks instead of 200. A lock and its escalation strike are set once per burst.
  - MCP routes return a fixed `server_error` description on 500 (register, authorize, token, jwks). The original error goes to the configured logger.

  Express and NestJS adapters (also on main): the per-mount handler cache is keyed by the lowercased mount and capped at 32 mounts, so request-chosen spellings of `req.baseUrl` no longer build a handler (guard, admission, compiled routes) each.

## 5.1.0

### Minor Changes

- 2c6f86d: Express, Fastify and NestJS adapters now rate limit requests in three tiers and reject cross-site writes made with a cookie session. New options on every adapter: `rateLimit`, `trustedOrigins` and `csrf`. Both checks are on by default; set `rateLimit: false` or `csrf: false` to opt out.

### Patch Changes

- 292ec38: Forward the `DPoP-Nonce` header on `/mcp/token` error responses so DPoP clients can complete the `use_dpop_nonce` retry, and allow the `DPoP` request header and expose `DPoP-Nonce` and `WWW-Authenticate` in the MCP CORS headers.
- d303a84: Share the rate limit and cross-site refusal writer between the Express and NestJS adapters.
- 43e6252: Fastify now passes the real request method to the rate limit and cross-site checks (it was always GET, so writes were counted as reads and the cross-site check never ran). Express and NestJS skip re-encoding the parsed body for those checks.

## 5.0.1

### Patch Changes

- 1fa2338: Scope management routes to the signed in owner when the default guard is used. With the default session resolver, `/agents`, `/delegations`, `/audit`, `/dashboard` and `POST /authorize` only act on the caller's own agents, delegations and audit rows, and `POST /agents` requires `ownerId` to be the caller. A custom `authenticate` resolver behaves as before. Core adds `guard.resolve()` and the `AdapterScope` helper so the other adapters can adopt the same checks, and `audit.export()` accepts a `userId` filter.
- 1fa2338: Resolve the client IP through the trusted proxy helper. The hono and express adapters no longer read `X-Forwarded-For` or `X-Real-IP` directly. By default forwarded headers are ignored (Express still falls back to `req.ip`), so an `ipAllowlist` constraint denies when the IP is unknown. Pass `trustedProxy: { trustedProxyCount }` or `trustedProxy: { trustedHeader }` to the adapter to match your proxy setup.

## 5.0.0

### Major Changes

- 4e37e17: Security: the framework adapters no longer serve the management routes anonymously.

  BREAKING (adapters): `/agents`, `/delegations`, `/audit`, `/dashboard` and `POST /authorize` now require an authenticated caller. Pass `authenticate: (request) => ({ id }) | null` to the adapter, or configure `auth.session` on `createTheAuth` to accept any valid session. With neither, the adapter throws when it is created. For local development only, `allowUnauthenticated: true` restores the old behavior and logs a warning. `/authorize/token`, MCP, password reset, email verification and plugin routes are unchanged.

  Other fixes:

  - hono and fastify: plugin routes now work when the adapter is mounted under a prefix (`app.route("/x", theAuthHono(...))`, `register(plugin, { prefix })`) instead of returning 404.
  - core: `plugins: [magicLink(...)]` (and the email OTP, 2FA, passkey, API key and organization plugins) now create their tables, matching the config-key form.
  - core: new `createAdapterGuard` and `isProtectedAdapterPath` exports used by every adapter.
  - create-theauth-app: templates pin `@glinr/*` packages to the versions in this release instead of stale ranges, list `sql.js` (the driver behind `provider: "sqlite"`) and `zod`, and the hono-mcp template protects its management routes with an `ADMIN_API_KEY`. The next-saas catch-all route now passes the TheAuth instance to the adapter.

### Patch Changes

- 4e37e17: Edge case hardening and opt-in session features.

  - Security: single-use credentials (magic links, email OTP attempts and codes, one-time tokens, OAuth state, SIWE nonces) are claimed atomically, so concurrent requests cannot redeem the same one twice.
  - Security: the OAuth plugin links a provider login to an existing account by email only when the provider and the local account are both verified. Otherwise it returns 409. `linkAccount` refuses to move a provider account to a different user. New accounts store `emailVerified` from the provider instead of always true.
  - Security: `withRateLimit` and the OAuth proxy use the trusted proxy rules and ignore `x-forwarded-for` and `x-real-ip` by default. Behind a proxy, set `trustedProxy`.
  - Emails are normalized in one place across all email flows.
  - Express, NestJS and Nuxt adapters send each `Set-Cookie` as its own header. Express and NestJS plugin routes honor the mount prefix. Astro, Nuxt and SvelteKit dispatchers now serve plugin endpoints.
  - New and opt-in: session cookie cache, refresh token `reuseGracePeriod`, `allowedHosts` per-request base URL, `createStatelessSessions`, OIDC back-channel and RP-initiated logout helpers, shared SIWE nonce `storage`.

- Updated dependencies [4e37e17]
- Updated dependencies [4e37e17]
- Updated dependencies [4e37e17]
- Updated dependencies [4e37e17]
- Updated dependencies [4e37e17]
- Updated dependencies [36f15a3]
- Updated dependencies [4e37e17]
- Updated dependencies [4e37e17]
- Updated dependencies [4e37e17]
- Updated dependencies [4e37e17]
- Updated dependencies [20aafa0]
  - @glinr/theauth@0.7.0

## 4.0.0

### Minor Changes

- 0fa5b1e: Remove the legacy KavachOS naming. The deprecated `Kavach*` and `createKavach` exports are gone: use `TheAuth*` and `createTheAuth`. Environment variables are now `THEAUTH_*`, webhook headers `X-TheAuth-*`, cookies and the default API route use `theauth`, and database tables are `theauth_*` (existing `kavach_*` tables are renamed in place by `createTables`, no data is lost). `Auth*` aliases remain deprecated.

### Patch Changes

- 960fe89: Delegation requests whose permissions are not a subset of the parent's now return HTTP 400 with error code `DELEGATION_PERMISSION_SUBSET` instead of a 500. Core throws a typed `DelegationError` (codes `DELEGATION_PERMISSION_SUBSET` and `DELEGATION_DEPTH_EXCEEDED`) and every REST adapter maps it to a 400 using that code.
- Updated dependencies [960fe89]
- Updated dependencies [dfd31f9]
- Updated dependencies [5e53bdb]
- Updated dependencies [0fa5b1e]
- Updated dependencies [9861742]
  - @glinr/theauth@0.6.0

## 3.1.0

### Minor Changes

- TheAuth is now the canonical naming across the SDK (`TheAuthClient`,
  `TheAuthProvider`, `TheAuthError`, `createTheAuth`, and per-adapter
  equivalents like `theAuthExpress`/`theAuthHono`). This resolves a
  three-way naming collision: an earlier pass renamed `Kavach*` to `Auth*`,
  this pass supersedes that with `TheAuth*` as canonical.

  Non-breaking. Both `Auth*` and `Kavach*` names remain as deprecated
  aliases pointing at the same implementation and will keep working until
  a future major version. No behavior changed, only naming.

  Also fixes two adapters (`express`, `hono`) that were missed by the
  earlier `Auth*` rename entirely and still only exported `kavach`-prefixed
  names.

### Patch Changes

- Updated dependencies
  - @glinr/theauth@0.5.0

## 3.0.2

### Patch Changes

- Updated dependencies
  - theauth@0.4.2

## 3.0.1

### Patch Changes

- Updated dependencies
  - theauth@0.4.1

## 3.0.0

### Patch Changes

- Updated dependencies
  - theauth@0.4.0

## 2.0.0

### Patch Changes

- Updated dependencies
  - theauth@0.3.0

## 1.0.0

### Major Changes

- 94804ec: Launch wave B: explicit major alignment for adapters/plugins after core moves to the 0.1 line.

  Why major:

  - These packages are pre-1.0 and depend on core package version semantics.
  - Core 0.0.x -> 0.1.x is treated as breaking for dependent package versioning.

  Operator notes:

  - Publish this wave separately from the core/client 0.1.0 wave.
  - Keep `@glinr/theauth-dashboard` on its independent track.

### Patch Changes

- Updated dependencies [94804ec]
  - theauth@0.1.0
