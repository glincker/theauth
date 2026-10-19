# Changelog

## 1.0.0

### Major Changes

- a561306: Security fix: `@glinr/theauth-nextjs-auth` 0.2.0 and earlier have a session forgery vulnerability. The session cache cookie was unsigned JSON and `getServerSession` returned it without checking a session token with the backend, so any user could hand-write the cookie and be treated as any user or role. Every user of 0.2.0 or earlier must upgrade.

  Breaking changes:

  - `createAuthConfig` now requires `secret`, at least 32 bytes (for example `openssl rand -base64 48` in a server-only env var). It throws at construction when the secret is missing or too short.
  - The session cache cookie is now HMAC-SHA256 signed (keys derived with HKDF), bound to a hash of the session token and to an expiry no later than the session expiry, and verified in constant time. Any mismatch falls back to the backend. Old unsigned cookies are ignored (one extra backend call, no error). `getServerSession` also returns null without a session token regardless of other cookies.
  - Cookies are `Secure` by default and no longer depend on `NODE_ENV`. Pass `secure: false` for localhost development over http only; cookies are forced Secure on https requests. `isProd` now only controls the `__Host-` name prefix. The cache cookie uses the `__Host-` prefix when the prefix is in use.
  - Cookie expiry on sign-out and refresh failure now sets `Secure` so browsers accept clearing `__Host-` cookies.

  - The middleware gate now requires a signed marker cookie (HMAC of the token under an HKDF derived key, Web Crypto only, no backend call), so an arbitrary token cookie no longer passes. It is still not authorization: use `getServerSession`. Sessions without the marker must refresh once.
  - CSRF is now a real signed double submit: HMAC tokens bound to the session token, verified in constant time (`verifyCsrfRequest`), enforced by `createSignOutHandler(csrfToken)` and the new `createSignOutRouteHandler`. `setSessionCookies` is async, no longer takes `csrfToken` and returns the signed token; `generateCsrfToken` is deprecated.
  - Plain cookie names are ignored once the `__Host-` names are in use (cookie shadowing, subdomain injection). Migrate with `legacyCookieNames: true` (default false), which accepts plain only when the `__Host-` cookie is absent.

  Also added: `safeRedirectPath` for `?next=` handling, and `withAuth` rejects a `signInPath` that is not a same-origin path. Workaround on old versions: set `cookieCacheMaxAgeMs: 0`.

### Minor Changes

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

## 0.2.0

### Minor Changes

- 0fa5b1e: Remove the legacy KavachOS naming. The deprecated `Kavach*` and `createKavach` exports are gone: use `TheAuth*` and `createTheAuth`. Environment variables are now `THEAUTH_*`, webhook headers `X-TheAuth-*`, cookies and the default API route use `theauth`, and database tables are `theauth_*` (existing `kavach_*` tables are renamed in place by `createTables`, no data is lost). `Auth*` aliases remain deprecated.

All notable changes to `@glinr/theauth-nextjs-auth` will be documented in this file.

This file follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Security

- **Fixed session forgery in 0.2.0 and earlier.** The session cache cookie was unsigned JSON that `getServerSession` trusted without a session token. It is now HMAC-SHA256 signed, bound to the session token and an expiry, and verified in constant time; anything else is ignored and the backend is asked. Unsigned legacy cookies are treated as no cache.

- **Middleware gate verifies a signed marker.** The token cookie alone no longer counts as signed in: a `{prefix}-gate` cookie (HMAC of the token, derived key, Web Crypto only) must verify, so an arbitrary cookie cannot pass. Still a UX gate: use `getServerSession` for authorization.
- **Signed CSRF double submit.** Tokens are HMAC signed and bound to the session token, verified in constant time by `verifyCsrfRequest`, enforced by `createSignOutHandler` and the new `createSignOutRouteHandler`. Missing, mismatched, forged and cross-session tokens are rejected.
- **Plain cookie names ignored under `__Host-`.** Cookie shadowing and subdomain injection no longer work. Migration: `legacyCookieNames: true` (default false).

### Breaking

- `createAuthConfig` requires `secret` (at least 32 bytes) and throws otherwise.
- Cookies are `Secure` by default regardless of `NODE_ENV`. Use `secure: false` for localhost development. `isProd` now only affects cookie name prefixes.
- `setSessionCookies` is async, no longer takes `csrfToken`, and returns the signed CSRF token. `generateCsrfToken` is deprecated.
- `createSignOutHandler` returns `(csrfToken?: string)` and refuses without a valid signed token. Sessions without the new marker cookie fail the middleware gate until refreshed.
- Plain `{prefix}-token`/`-csrf` cookies are ignored when `__Host-` names are in use unless `legacyCookieNames: true`.
- The cache cookie name gets the `__Host-` prefix when the prefix is in use.

### Added

- `safeRedirectPath` open-redirect guard; `withAuth` rejects a non same-origin `signInPath`.

### Changed

- **`createSignOutHandler`** replaces `createSignOutAction` as the primary export name. The previous implementation inlined a `"use server"` directive inside the returned function body, which caused a Next.js build error when the adapter was reachable from any client-component graph (`It is not allowed to define inline "use server" annotated Server Actions in Client Components`). The new implementation returns a plain `async function` with no inline directive. Consumers must wrap it in their own `"use server"` file. See README §4 Sign out.
- `createSignOutAction` is retained as a **deprecated alias** for one release cycle and will be removed in v0.2.

## [0.1.0] - 2026-05-02

### Added

New package: initial release.

**What it is:** A focused Next.js (14/15/16) adapter for projects whose auth backend lives elsewhere (Spring, Rails, Hono, Go, etc.). Distinct from `@glinr/theauth-nextjs` which bundles the agent-management runtime; this package covers the "I already have a backend, just give me cookie + session + refresh on the FE" case.

**Server-side API (from main import):**

- `createAuthConfig<TUser>()`: typed factory. Pass `backendUrl`, `appUrl`, `endpoints`, `cookies.sessionPrefix`, and a `mapUser` function; get a fully typed config used by every other helper.
- `getServerSession(config)`: React.cache memoized + cookie-cached (5 min default TTL, configurable, disable by setting `sessionCacheTtlMs: 0`). Reads from the cookie cache first; falls back to the `/me` endpoint.
- `refreshSession(config)`: proactive token rotation. Calls the `/refresh` endpoint, writes the new token into cookies.
- `fetchWithRefresh(config, url, init?)`: drop-in `fetch` wrapper that retries once on 401 after attempting `refreshSession`.
- `graphqlWithRefresh(config, query, variables?)`: same retry logic wired for GraphQL.
- `buildAuthHeaders(config)`: server-safe header builder (reads the access-token cookie on the server; does not touch `document.cookie`).
- `buildClientHeaders()`: client-safe header builder (reads `document.cookie`; safe to call from Client Components).
- `createSignOutAction(config)`: returns a Next.js Server Action factory that calls the backend `/logout` endpoint and clears all session cookies.

**Edge-runtime middleware (from `/middleware` sub-export):**

- `withAuth(config, options?)`: wraps your Next.js middleware function. Checks for the session cookie and redirects to `signInUrl` if absent. Edge-runtime safe (no Node-only APIs).

**Cookie policy:**

- Production: cookies are named `__Host-{prefix}-token` (Secure, SameSite=Lax, no Domain attribute, required by the `__Host-` prefix spec).
- Development: plain `{prefix}-token` names (browsers reject `__Host-` without Secure on HTTP localhost).

**Test coverage:** 26 tests across three suites (jwt: 9, cookies: 11, refresh: 6).

**Build output:** 12.77 KB main bundle, 5.51 KB middleware sub-export (ESM only, tree-shakeable).

[0.1.0]: https://github.com/glincker/theauth/releases/tag/%40theauth%2Fnextjs-auth%400.1.0
