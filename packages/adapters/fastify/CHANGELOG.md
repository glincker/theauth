# @glinr/theauth-fastify

## 6.0.0

### Major Changes

- a561306: Rebuilt on the core HTTP handler (`createTheAuthHandler` from `@glinr/theauth/http`) using `toWebRequest` and `sendWebResponse`. `theAuthFastify` is now thin glue and serves every route, including `POST /mcp/revoke`, `GET /mcp/jwks` and `POST /explain`. New `requireScope(auth, { action, resource })` preHandler and `getAgent(request)`.

  Upgrade notes:

  - `TheAuthFastifyOptions` is now the core `TheAuthHandlerOptions` (`mcp`, `basePath`, `routes`, `maxBodyBytes` and the existing security options). `basePath` defaults to the prefix the plugin is registered under.
  - Inside the plugin the request body is no longer parsed by Fastify (the handler reads it itself). Your own routes outside the plugin are unaffected.
  - Removed the deprecated `authFastify` and `AuthFastifyOptions`. Use `theAuthFastify` and `TheAuthFastifyOptions`.
  - `POST /authorize/token` answers 401 for `invalid_token`, `agent_not_found`, `agent_revoked` and `agent_expired`, and 403 for every other denial.
  - The client IP now comes from the socket peer address, or from forwarded headers when `trustedProxy` is set.

### Patch Changes

- a561306: Core: `toWebRequest` now records the socket remote address out of band, exposed as `peerAddressOf(request)`. Without `trustedProxy` the handler, rate limiter and `requireAgent` use that peer address as the client IP, so per-IP limits and `ipAllowlist` work on direct Express, Fastify and NestJS deployments. Forwarded headers are still only believed when `trustedProxy` is set. `requireAgent` accepts `trustedProxy`.

  Breaking: `GET /audit/export?userId=<other user>` by a caller limited to their own resources is now `403` with `{ error: { code, message } }` instead of silently returning the caller's rows.

  Fastify: the handler is built once at registration, so `allowUnauthenticated` warns once. `requireScope` matches `ipAllowlist` against the socket peer by default. The fail-closed check without an authenticator now surfaces when the plugin registers instead of at `theAuthFastify(...)`.

## 5.1.0

### Minor Changes

- 2c6f86d: Express, Fastify and NestJS adapters now rate limit requests in three tiers and reject cross-site writes made with a cookie session. New options on every adapter: `rateLimit`, `trustedOrigins` and `csrf`. Both checks are on by default; set `rateLimit: false` or `csrf: false` to opt out.

### Patch Changes

- 292ec38: Forward the `DPoP-Nonce` header on `/mcp/token` error responses so DPoP clients can complete the `use_dpop_nonce` retry, and allow the `DPoP` request header and expose `DPoP-Nonce` and `WWW-Authenticate` in the MCP CORS headers.
- 43e6252: Fastify now passes the real request method to the rate limit and cross-site checks (it was always GET, so writes were counted as reads and the cross-site check never ran). Express and NestJS skip re-encoding the parsed body for those checks.

## 5.0.1

### Patch Changes

- 1fa2338: Scope management routes to the signed in owner when the default guard is used, and resolve the client IP through the trusted proxy helper.

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

## 3.0.3

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
