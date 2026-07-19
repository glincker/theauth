---
title: Sessions
description: Cookie sessions, JWT tokens, ephemeral agent sessions, CSRF protection, session freshness, and lifecycle management.
---

# Sessions

TheAuth has three session types:

- **Cookie sessions** for human users in browsers. A signed JWT sits in an `httpOnly` cookie. The session record lives in your database so you can revoke it instantly.
- **JWT sessions** for SPAs, mobile apps, and server-to-server flows. Stateless access tokens paired with rotating refresh tokens.
- **Ephemeral agent sessions** for AI agents (Claude, GPT-with-browsing, operator loops). Short-lived, budget-bounded credentials that expire by time or action count, whichever comes first.

This page covers cookie sessions and JWT sessions. Ephemeral agent sessions are documented on the [Agent Identity](agents.md) page.

## Cookie sessions

### Configure the session manager

Pass `createCookieSessionManager` a config object and your `kavach.db` instance. The manager handles creation, validation, refresh, and revocation.

```typescript
import { createTheAuth } from '@glinr/theauth';
import { createCookieSessionManager } from '@glinr/theauth/auth';

export const kavach = await createTheAuth({
  database: { provider: 'postgres', url: process.env.DATABASE_URL! },
  secret: process.env.KAVACH_SECRET!,
  baseUrl: 'https://auth.example.com',
});

export const sessions = createCookieSessionManager({
  sessionName: 'kavach_session',
  maxAge: 7 * 24 * 60 * 60, // 7 days in seconds
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'lax',
  db: kavach.db,
  secret: process.env.KAVACH_SECRET!,
});
```

### Session freshness

Some operations require a "fresh" session: the session was created or re-authenticated recently. Examples include password changes and passkey registration.

By default, a session is considered fresh if it is less than 5 minutes old. Configure this via the `freshAge` option on the session config:

```typescript
auth: {
  session: {
    secret: process.env.SESSION_SECRET!,
    maxAge: 60 * 60 * 24 * 7,
    freshAge: 300, // 5 minutes (default)
  },
},
```

### CSRF protection

Cookie sessions include CSRF protection by default. Each session is issued with a CSRF token that must be present in the `X-CSRF-Token` header on state-mutating requests (POST, PATCH, DELETE). Clients reading the token via the session endpoint can include it in subsequent requests.

## JWT sessions

For SPAs, mobile clients, and server-to-server flows where cookies are not practical.

```typescript
import { createTheAuth } from '@glinr/theauth';
import { jwt } from '@glinr/theauth/auth';

const kavach = await createTheAuth({
  database: { provider: 'postgres', url: process.env.DATABASE_URL! },
  secret: process.env.KAVACH_SECRET!,
  plugins: [
    jwt({
      accessTokenTtl: 3600,    // 1 hour
      refreshTokenTtl: 604800, // 7 days
    }),
  ],
});
```

Access tokens are short-lived. Refresh tokens rotate on each use (refresh token rotation). A compromised refresh token can only be used once before it is invalidated.

## Session config reference

| Option | Type | Default | Description |
|---|---|---|---|
| `secret` | `string` | required | Signing secret for session JWTs. Min 32 characters. |
| `maxAge` | `number` | `604800` (7 days) | Session lifetime in seconds. |
| `cookieName` | `string` | `'kavach_session'` | Name of the session cookie. |
| `freshAge` | `number` | `300` (5 minutes) | Maximum session age in seconds to be considered fresh. |

## Related pages

- [Agent Identity](agents.md)
- [Configuration](../reference/configuration.md)
- [Auth: Email and Password](../guides/auth/email-password.md)
