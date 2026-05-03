# @kavachos/nextjs-auth

Next.js 14/15/16 adapter for projects with an **external auth backend**. Handles cookies, proactive token refresh, CSRF double-submit, `getServerSession`, and middleware — all typed end-to-end.

## When to use this vs `@kavachos/nextjs`

| | `@kavachos/nextjs-auth` | `@kavachos/nextjs` |
|---|---|---|
| **Use case** | You have an external auth backend (Spring, Rails, Hono, Express, etc.) and need session management on the Next.js FE | You're using the KavachOS agent-management runtime with its built-in auth |
| **Auth source** | External REST API (`/api/auth/*`) | In-process KavachOS SDK |
| **Zero deps on** | `kavachos` core, `@kavachos/nextjs` | — |
| **Key exports** | `getServerSession`, `withAuth`, `refreshSession`, `fetchWithRefresh` | `kavachNextjs()` handler |

vs **next-auth**: next-auth requires a database adapter and runs auth in-process. Use `@kavachos/nextjs-auth` when your backend already handles session state and you just want the FE plumbing.

vs **better-auth**: better-auth also runs in-process (or via a hosted service). Use this adapter when you cannot or do not want to run auth logic inside the Next.js process — only a REST call over the wire.

## Quickstart

```bash
pnpm add @kavachos/nextjs-auth
```

### 1. Create your config

```ts
// src/lib/auth/config.ts
import "server-only";
import { createAuthConfig } from "@kavachos/nextjs-auth";

export const authConfig = createAuthConfig({
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
import { getServerSession } from "@kavachos/nextjs-auth";
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
import { withAuth } from "@kavachos/nextjs-auth/middleware";
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

```ts
// src/lib/auth/actions.ts
import "server-only";
import { createSignOutAction } from "@kavachos/nextjs-auth";
import { authConfig } from "./config";

export const signOut = createSignOutAction(authConfig);
```

```tsx
// In any component
import { signOut } from "@/lib/auth/actions";
<button onClick={signOut}>Sign out</button>
```

## API Reference

### `createAuthConfig(input)` → `ResolvedAuthConfig<TUser>`

Factory that resolves all defaults. Returns an immutable config object passed to every other function.

| Option | Type | Default | Description |
|---|---|---|---|
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
| `isProd` | `boolean` | `NODE_ENV === "production"` | Controls `__Host-` cookie prefix |

### `getServerSession(config)` → `Promise<AuthSession<TUser> | null>`

Server-only. Returns the authenticated session or null.

Performance: memoized per render via `React.cache()` + cookie cache (5 min TTL by default). On cache miss, calls `GET /api/auth/me`. On 401, attempts one token refresh and retries.

```ts
const session = await getServerSession(authConfig);
// session.user — your TUser shape
// session.expiresAt — Date | null (from JWT exp claim)
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

### `createSignOutAction(config)` → `() => Promise<{ success: boolean }>`

Server-only. Returns a Server Action that calls the backend logout endpoint and clears all auth cookies.

### `buildAuthHeaders(config, opts?)` → `Promise<Record<string, string>>`

Server-only. Returns headers for server → backend calls: `Authorization`, `Origin`, `X-Client-Origin`, `X-Tenant-Domain`, `X-CSRF-Token`, `Cookie`.

### `buildClientHeaders(config)` → `Record<string, string>`

Client-safe. Returns minimal headers for browser → backend fetches (no auth headers, no Origin). The browser sends auth cookies and Origin automatically.

### `withAuth(config, options?)` (from `@kavachos/nextjs-auth/middleware`)

Edge-runtime safe. Returns a Next.js middleware function.

Options:
- `protectedPaths: string[]` — paths requiring auth; redirects to `signInPath?next=<path>` when unauthenticated
- `signInPath: string` — default `"/signin"`
- `refreshTimeoutMs: number` — default `4000`

## TypeScript — custom User shape

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

## Cookie cache tradeoffs

The session cache stores `{ user, expiresAt, stampedAt }` in a short-lived httpOnly cookie. On cache hit (within `cookieCacheMaxAgeMs`), `getServerSession` returns immediately without calling the backend.

**Benefits**: reduces backend load; avoids 50–200ms network hop per RSC render.

**Tradeoffs**:
- Stale user data for up to `cookieCacheMaxAgeMs`. Acceptable for display data (name, email); not suitable for permission checks that need real-time accuracy.
- v0.1 stores plain JSON (no HMAC signing). The cookie is httpOnly+sameSite=lax — an attacker needs TLS access to read or forge it. v0.2 will add HMAC-SHA256 signing for defence-in-depth.
- Set `cookieCacheMaxAgeMs: 0` to disable caching entirely (every RSC render hits the backend).

Better-auth uses the same approach: a `session_data` cookie with configurable `maxAge` avoiding DB round-trips. Their v1 uses compact base64url+HMAC, JWT, or JWE encoding. We start with plain JSON for simplicity.

## CSRF protection

Uses the double-submit cookie pattern:
1. On login, the server sets a CSRF token in a **non-httpOnly** cookie so JS can read it.
2. On mutating requests, the client echoes it as `X-CSRF-Token`.
3. The backend compares header value vs. cookie value; they must match.
4. An attacker on a different origin cannot read the cookie → cannot forge the header.

`buildAuthHeaders` includes both `X-CSRF-Token` and a `Cookie` echo of the plain (non-`__Host-`) CSRF cookie name, matching KavachOS Spring backends that use a `CsrfDoubleSubmitFilter`.

## Cookie prefix policy

- **Production (HTTPS)**: `__Host-{prefix}-token`, `__Host-{prefix}-csrf`
  - `__Host-` requires `Secure`, no `Domain`, `Path=/` — maximally restrictive
- **Development (HTTP)**: `{prefix}-token`, `{prefix}-csrf`
  - Browsers reject `__Host-` without `Secure`; plain names are used instead
- **Refresh token**: never `__Host-` prefixed (longer-lived, `sameSite=lax`)
- Auto-detected from `isProd` / `NODE_ENV`
