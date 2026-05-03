# Changelog

All notable changes to `@kavachos/nextjs-auth` will be documented in this file.

This file follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [0.1.0] — 2026-05-02

### Added

New package — initial release.

**What it is:** A focused Next.js (14/15/16) adapter for projects whose auth backend lives elsewhere (Spring, Rails, Hono, Go, etc.). Distinct from `@kavachos/nextjs` which bundles the agent-management runtime; this package covers the "I already have a backend, just give me cookie + session + refresh on the FE" case.

**Server-side API (from main import):**

- `createAuthConfig<TUser>()` — typed factory. Pass `backendUrl`, `appUrl`, `endpoints`, `cookies.sessionPrefix`, and a `mapUser` function; get a fully typed config used by every other helper.
- `getServerSession(config)` — React.cache memoized + cookie-cached (5 min default TTL, configurable, disable by setting `sessionCacheTtlMs: 0`). Reads from the cookie cache first; falls back to the `/me` endpoint.
- `refreshSession(config)` — proactive token rotation. Calls the `/refresh` endpoint, writes the new token into cookies.
- `fetchWithRefresh(config, url, init?)` — drop-in `fetch` wrapper that retries once on 401 after attempting `refreshSession`.
- `graphqlWithRefresh(config, query, variables?)` — same retry logic wired for GraphQL.
- `buildAuthHeaders(config)` — server-safe header builder (reads the access-token cookie on the server; does not touch `document.cookie`).
- `buildClientHeaders()` — client-safe header builder (reads `document.cookie`; safe to call from Client Components).
- `createSignOutAction(config)` — returns a Next.js Server Action factory that calls the backend `/logout` endpoint and clears all session cookies.

**Edge-runtime middleware (from `/middleware` sub-export):**

- `withAuth(config, options?)` — wraps your Next.js middleware function. Checks for the session cookie and redirects to `signInUrl` if absent. Edge-runtime safe (no Node-only APIs).

**Cookie policy:**

- Production: cookies are named `__Host-{prefix}-token` (Secure, SameSite=Lax, no Domain attribute — required by the `__Host-` prefix spec).
- Development: plain `{prefix}-token` names (browsers reject `__Host-` without Secure on HTTP localhost).

**Test coverage:** 26 tests across three suites (jwt: 9, cookies: 11, refresh: 6).

**Build output:** 12.77 KB main bundle, 5.51 KB middleware sub-export (ESM only, tree-shakeable).

[0.1.0]: https://github.com/kavachos/kavachos/releases/tag/%40kavachos%2Fnextjs-auth%400.1.0
