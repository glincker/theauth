# @glinr/theauth-nextjs-auth

[![npm](https://img.shields.io/npm/v/@glinr/theauth-nextjs-auth?style=flat&colorA=000000&colorB=000000&label=npm)](https://www.npmjs.com/package/@glinr/theauth-nextjs-auth) [![downloads](https://img.shields.io/npm/dm/@glinr/theauth-nextjs-auth?style=flat&colorA=000000&colorB=000000&label=downloads)](https://www.npmjs.com/package/@glinr/theauth-nextjs-auth) [![docs](https://img.shields.io/badge/docs-docs.theauth.dev-000000?style=flat)](https://docs.theauth.dev/adapters/nextjs) [![license](https://img.shields.io/badge/license-MIT-000000?style=flat)](https://github.com/glincker/theauth/blob/main/LICENSE)

[npm](https://www.npmjs.com/package/@glinr/theauth-nextjs-auth) · [Source](https://github.com/glincker/theauth/tree/main/packages/adapters/nextjs-auth) · [All packages](https://github.com/glincker/theauth#packages)

Next.js 14/15/16 adapter for projects with an **external auth backend**. Handles cookies, proactive token refresh, CSRF double-submit, `getServerSession`, and middleware, all typed end-to-end.

Part of [theAuth](https://theauth.dev), open-source auth for AI agents and humans. Docs: [docs.theauth.dev](https://docs.theauth.dev).

## When to use this vs `@glinr/theauth-nextjs`

| | `@glinr/theauth-nextjs-auth` | `@glinr/theauth-nextjs` |
|---|---|---|
| **Use case** | You have an external auth backend (Spring, Rails, Hono, Express, etc.) and need session management on the Next.js FE | You're using the theAuth agent-management runtime with its built-in auth |
| **Auth source** | External REST API (`/api/auth/*`) | In-process theAuth SDK |
| **Zero deps on** | `@glinr/theauth` core, `@glinr/theauth-nextjs` | none |
| **Key exports** | `getServerSession`, `withAuth`, `refreshSession`, `fetchWithRefresh` | `theAuthNextjs()` handler |

vs **next-auth**: next-auth requires a database adapter and runs auth in-process. Use `@glinr/theauth-nextjs-auth` when your backend already handles session state and you just want the FE plumbing.

vs **better-auth**: better-auth also runs in-process (or via a hosted service). Use this adapter when you cannot or do not want to run auth logic inside the Next.js process, only a REST call over the wire.

> **Security: upgrade from 0.2.0 and earlier.** Versions up to and including 0.2.0 trusted an
> unsigned session cache cookie in `getServerSession`, so a user could forge it and be treated as
> any user or role. Fixed in 1.0.0, which requires a `secret`. See [Upgrading](#upgrading-from-020-breaking).

## Quickstart

```bash
pnpm add @glinr/theauth-nextjs-auth
```

### 1. Create your config

```ts
// src/lib/auth/config.ts
import "server-only";
import { createAuthConfig } from "@glinr/theauth-nextjs-auth";

export const authConfig = createAuthConfig({
  // Required, at least 32 bytes, server-only. Generate with: openssl rand -base64 48
  secret: process.env.THEAUTH_SESSION_SECRET!,
  backendUrl: process.env.NEXT_PUBLIC_API_BASE_URL!,
  appUrl: process.env.NEXT_PUBLIC_APP_URL!,
  tenantDomain: "myapp.com",
  endpoints: {
    me: "/api/v1/auth/me",
    refresh: "/api/auth/refresh",
    signOut: "/api/v1/auth/logout",
  },
  cookies: { sessionPrefix: "myapp" },
  mapUser: (raw) => {
    if (!raw || typeof raw !== "object") return null;
    const r = raw as Record<string, unknown>;
    return { id: String(r.id), email: String(r.email ?? ""), name: String(r.name ?? "") };
  },
});
```

### 2. Get the session in Server Components

```ts
// app/dashboard/page.tsx
import { getServerSession } from "@glinr/theauth-nextjs-auth";
import { authConfig } from "@/lib/auth/config";
import { redirect } from "next/navigation";

export default async function DashboardPage() {
  const session = await getServerSession(authConfig);
  if (!session) redirect("/signin");
  return <h1>Hello {session.user.name}</h1>;
}
```

### 3. Add middleware

```ts
// middleware.ts (project root)
import { withAuth } from "@glinr/theauth-nextjs-auth/middleware";
import { authConfig } from "@/lib/auth/config";

export default withAuth(authConfig, {
  protectedPaths: ["/app", "/dashboard"],
  signInPath: "/signin",
});

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
```

### 4. Sign out

The adapter returns a plain async function: you add `"use server"` in **your own** file so Next.js can statically analyse it:

```ts
// src/app/auth/actions.ts   ← your file, your directive
"use server";
import { createSignOutHandler } from "@glinr/theauth-nextjs-auth";
import { authConfig } from "@/lib/auth/config.server";

export const signOut = createSignOutHandler(authConfig);
```

```tsx
// In any component
import { signOut } from "@/app/auth/actions";
<button onClick={signOut}>Sign out</button>
```

#### Why no inline `"use server"`?

The adapter is imported by both server and client module graphs (e.g. a client component that imports a shared config file). Next.js forbids inline `"use server"` directives in any module reachable from a client component. The compiler errors out. By keeping the directive out of the adapter, the compiled output is a plain async function that is safe to import anywhere. The `"use server"` annotation belongs in **consumer code** (a dedicated `actions.ts` file), where Next.js can statically verify it belongs to a server-action boundary.

## API Reference

### `createAuthConfig(input)` → `ResolvedAuthConfig<TUser>`

Factory that resolves all defaults. Returns an immutable config object passed to every other function.

| Option | Type | Default | Description |
|---|---|---|---|
| `secret` | `string` | required | At least 32 bytes. Signs the session cache cookie (HMAC-SHA256). `createAuthConfig` throws when missing or short |
| `secure` | `boolean` | `true` | `Secure` cookie attribute. Never derived from `NODE_ENV`. Set `false` only for localhost development over http. Always forced on for https requests |
| `backendUrl` | `string` | required | Backend base URL, no trailing slash |
| `appUrl` | `string` | required | Public app URL for Origin headers |
| `tenantDomain` | `string` | `""` | Sent as `X-Tenant-Domain` |
| `endpoints.me` | `string` | `"/api/auth/me"` | GET current user |
| `endpoints.refresh` | `string` | `"/api/auth/refresh"` | POST refresh token |
| `endpoints.signOut` | `string` | `"/api/auth/logout"` | POST sign out |
| `cookies.sessionPrefix` | `string` | `"glinr"` | Cookie name prefix |
| `cookies.refresh` | `string` | `"{prefix}-refresh-token"` | Refresh cookie name |
| `cookieCacheMaxAgeMs` | `number` | `300_000` (5 min) | Session cache TTL, `0` to disable |
| `expiryRefreshBufferS` | `number` | `60` | Proactive refresh threshold |
| `mapUser` | `(raw) => TUser \| null` | identity | Map backend payload to your User type |
| `isProd` | `boolean` | `NODE_ENV === "production"` | Controls only the `__Host-` cookie name prefix (used when `secure` is not disabled). Does not affect `Secure` |

### `getServerSession(config)` → `Promise<AuthSession<TUser> | null>`

Server-only. Returns the authenticated session or null.

Performance: memoized per render via `React.cache()` + signed cookie cache (5 min TTL by default). Without a session token it returns null immediately. On cache miss, calls `GET /api/auth/me`. On 401, attempts one token refresh and retries.

```ts
const session = await getServerSession(authConfig);
// session.user: your TUser shape
// session.expiresAt: Date | null (from JWT exp claim)
```

### `refreshSession(config)` → `Promise<RefreshResult | null>`

Server-only (Server Actions / Route Handlers). Reads the refresh token cookie, calls the backend, writes fresh cookies via `next/headers`. Returns null on failure or missing cookie.

### `fetchWithRefresh(config, path, init?)` → `Promise<Response>`

Server-only. Authenticated `fetch` with 401-retry. Builds auth headers, fires the request; on 401, refreshes once and retries.

### `graphqlWithRefresh<T>(config, document, variables?, opts?)` → `Promise<T>`

Server-only. Like `fetchWithRefresh` but for GraphQL. Throws `GraphQLRequestError` on GraphQL errors.

```ts
const data = await graphqlWithRefresh<MyQuery>(authConfig, MY_QUERY, { id: "123" });
```

### `createSignOutHandler(config)` → `() => Promise<{ success: boolean }>`

Server-only. Returns an async function that calls the backend logout endpoint (best-effort) and clears all auth cookies. Does **not** include an inline `"use server"` directive; wrap it in your own `"use server"` file (see [Sign out](#4-sign-out)).

> `createSignOutAction` is a deprecated alias for `createSignOutHandler`.

### `buildAuthHeaders(config, opts?)` → `Promise<Record<string, string>>`

Server-only. Returns headers for server → backend calls: `Authorization`, `Origin`, `X-Client-Origin`, `X-Tenant-Domain`, `X-CSRF-Token`, `Cookie`.

### `buildClientHeaders(config)` → `Record<string, string>`

Client-safe. Returns minimal headers for browser → backend fetches (no auth headers, no Origin). The browser sends auth cookies and Origin automatically.

### `withAuth(config, options?)` (from `@glinr/theauth-nextjs-auth/middleware`)

Edge-runtime safe. Returns a Next.js middleware function.

Options:
- `protectedPaths: string[]`: paths requiring auth; redirects to `signInPath?next=<path>` when unauthenticated
- `signInPath: string`: default `"/signin"`
- `refreshTimeoutMs: number`: default `4000`

## TypeScript: custom User shape

```ts
interface MyUser {
  id: string;
  email: string;
  role: "admin" | "member";
}

export const authConfig = createAuthConfig<MyUser>({
  backendUrl: "...",
  appUrl: "...",
  mapUser: (raw) => {
    const r = raw as Record<string, unknown>;
    if (!r.id) return null;
    return { id: String(r.id), email: String(r.email), role: r.role as "admin" | "member" };
  },
});

// getServerSession returns AuthSession<MyUser>
const session = await getServerSession(authConfig);
session?.user.role; // typed as "admin" | "member"
```

## Cookie cache

The session cache stores `{ user, expiresAt, stampedAt }` in a short-lived cookie. On a cache hit (within `cookieCacheMaxAgeMs`), `getServerSession` returns without calling the backend.

How it is protected:
- The value is `v1.<payload>.<HMAC-SHA256>`, signed with keys derived from `secret` via HKDF-SHA256 (separate keys for the cookie MAC and for the token binding).
- It is bound to an HMAC of the current session token, so a cache cookie cannot be replayed with another user's token, and it is never used when there is no session token.
- It carries a hard expiry: the earlier of `cookieCacheMaxAgeMs` and the session expiry. The cookie `Max-Age` matches.
- Verification is constant time. Any failure (bad signature, wrong token, expired, malformed, oversized, or an old unsigned 0.2.0 cookie) means "no cache": one extra backend call, no error.
- Attributes: `HttpOnly`, `Secure` (default), `SameSite=Lax`, `Path=/`, and the `__Host-` name prefix when `secure` is on and `isProd` is true. Entries over 3800 bytes are not cached.

Tradeoffs:
- The payload is signed, not encrypted. The user object is readable by whoever holds the cookie (it is `HttpOnly`, so page JavaScript cannot read it). Keep large or sensitive fields out of `mapUser`.
- Stale user data for up to `cookieCacheMaxAgeMs`. Not suitable for permission checks that need real-time accuracy: set `cookieCacheMaxAgeMs: 0` for those, or check on the backend.
- Rotating `secret` invalidates all cache cookies. Users only pay one backend call.

## Upgrading from 0.2.0 (breaking)

0.2.0 and earlier have a **session forgery vulnerability**: the cache cookie was unsigned JSON and `getServerSession` returned it without checking a session token with the backend. Anyone could hand-write the cookie and become any user or role. Upgrade now.

1. Generate a secret: `openssl rand -base64 48`, store it as a server-only environment variable.
2. Pass it: `createAuthConfig({ secret: process.env.THEAUTH_SESSION_SECRET!, ... })`.
3. Cookies are now `Secure` by default. On plain-http localhost set `secure: false` in development only.
4. Old unsigned cache cookies are ignored automatically. Until you upgrade, set `cookieCacheMaxAgeMs: 0` as a workaround (the legacy code then never reads the cache).

## Middleware is an optimistic gate

`withAuth` runs on the Edge without the backend. It treats any non-empty access token cookie as "signed in" for the `protectedPaths` redirect, so it is a UX gate, not authorization. Always call `getServerSession` (or the backend) in pages, layouts, route handlers and server actions before returning protected data.

Use `safeRedirectPath(next, fallback)` (exported from both entry points) on the `?next=` value in your sign-in page before redirecting, so only same-origin paths are followed. `withAuth` rejects a `signInPath` that is not a same-origin path.

## CSRF protection

Uses the double-submit cookie pattern:
1. On login, the server sets a CSRF token in a **non-httpOnly** cookie so JS can read it.
2. On mutating requests, the client echoes it as `X-CSRF-Token`.
3. The backend compares header value vs. cookie value; they must match.
4. An attacker on a different origin cannot read the cookie → cannot forge the header.

Limits: the CSRF cookie is not signed, and `buildAuthHeaders` echoes the same browser cookie into both header and cookie, so for calls proxied through Next.js the protection comes from `SameSite=Lax`, the `__Host-` prefix (blocks cookie tossing from subdomains) and Next.js's own Origin check on Server Actions, not from the double submit.

`buildAuthHeaders` includes both `X-CSRF-Token` and a `Cookie` echo of the plain (non-`__Host-`) CSRF cookie name, matching theAuth Spring backends that use a `CsrfDoubleSubmitFilter`.

## Cookie prefix policy

- **Production (HTTPS)**: `__Host-{prefix}-token`, `__Host-{prefix}-csrf`
  - `__Host-` requires `Secure`, no `Domain`, `Path=/`, maximally restrictive
- **Development (HTTP)**: `{prefix}-token`, `{prefix}-csrf`
  - Browsers reject `__Host-` without `Secure`; plain names are used instead
- **Refresh token**: never `__Host-` prefixed (longer-lived, `sameSite=lax`)
- Name prefix auto-detected from `isProd` / `NODE_ENV`; the `Secure` flag is on by default and independent of it

<!-- theauth:links -->
## Learn more

- [Next.js adapter](https://docs.theauth.dev/adapters/nextjs)
- [Quickstart](https://docs.theauth.dev/quickstart)
- [All packages](https://github.com/glincker/theauth#packages)
- [GitHub Discussions](https://github.com/glincker/theauth/discussions) for questions
- [Report a security issue](https://github.com/glincker/theauth/blob/main/SECURITY.md)
