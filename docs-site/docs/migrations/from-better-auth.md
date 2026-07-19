---
title: From better-auth
description: Switch a better-auth app to TheAuth. Maps betterAuth config, plugins, session types, and client hooks to TheAuth equivalents with before and after diffs.
---

# From better-auth

better-auth is a solid human-auth library. If your product now needs AI agents as first-class entities, an MCP OAuth 2.1 server, GDPR compliance exports, or trust scoring per agent, TheAuth is worth the switch. If you rely on an OAuth provider that better-auth covers but TheAuth does not ship first-class (17 first-class providers plus a generic OIDC factory as of 2026-04), you may want to wait.

## Concepts map

| better-auth | TheAuth |
|---|---|
| `auth = betterAuth({...})` | `kavach = createAuth({...})` |
| `User` | `User` + `AgentIdentity` (agents are a first-class entity, not an extension) |
| `Session` | `Session` + `AgentSession` + `EphemeralAgentSession` |
| `organization` plugin | `organization` plugin (same name, similar shape) |
| `admin` plugin | `admin` plugin (adds ban + impersonate-with-TTL) |
| `two-factor`, `passkey`, `magic-link`, `username`, `email-otp`, `phone-number`, `anonymous`, `siwe`, `device-authorization`, `one-tap` | All present with the same hook names |
| `api-key` plugin | `api-key-plugin` |
| `mcp` plugin (thin wrapper) | Built-in MCP OAuth 2.1 server with agent identity and delegation, no separate plugin |
| `@better-auth/agent-auth` | TheAuth core, no separate package |
| `sso`, `saml`, `scim`, `oidc-provider`, `openapi`, `jwt`, `custom-session`, `additional-fields`, `bearer` | All present under similar names |

## Server migration

### Next.js App Router

=== "Before (better-auth)"
    ```ts
    // lib/auth.ts
    import { betterAuth } from 'better-auth';
    import { organization, twoFactor } from 'better-auth/plugins';

    export const auth = betterAuth({
      database: { provider: 'postgresql', url: process.env.DATABASE_URL },
      emailAndPassword: { enabled: true },
      plugins: [organization(), twoFactor()],
    });
    ```

    ```ts
    // app/api/auth/[...all]/route.ts
    import { auth } from '@/lib/auth';
    import { toNextJsHandler } from 'better-auth/next-js';

    export const { GET, POST } = toNextJsHandler(auth);
    ```
=== "After (TheAuth)"
    ```ts
    // lib/kavach.ts
    import { createAuth } from '@glinr/theauth';
    import { organization, twoFactor } from '@glinr/theauth/plugins';

    export const kavach = createAuth({
      database: { provider: 'postgres', url: process.env.DATABASE_URL! },
      secret: process.env.KAVACH_SECRET!,
      baseUrl: process.env.AUTH_BASE_URL!,
      emailAndPassword: { enabled: true },
      plugins: [organization(), twoFactor()],
    });
    ```

    ```ts
    // app/api/kavach/[...kavach]/route.ts
    import { authNextjs } from '@glinr/theauth-nextjs';
    import { kavach } from '@/lib/kavach';

    const handlers = authNextjs(kavach);

    export const GET = handlers.GET;
    export const POST = handlers.POST;
    export const PATCH = handlers.PATCH;
    export const DELETE = handlers.DELETE;
    export const OPTIONS = handlers.OPTIONS;
    ```

### Hono

=== "Before (better-auth)"
    ```ts
    import { Hono } from 'hono';
    import { auth } from './lib/auth.js';

    const app = new Hono();

    app.on(['GET', 'POST'], '/api/auth/*', (c) => auth.handler(c.req.raw));
    ```
=== "After (TheAuth)"
    ```ts
    import { Hono } from 'hono';
    import { kavachHono } from '@glinr/theauth-hono';
    import { kavach } from './lib/kavach.js';

    const app = new Hono();

    app.route('/api/kavach', kavachHono(kavach));
    ```

## Data migration SQL

Copy users, accounts, and sessions from better-auth tables to TheAuth tables:

```sql
-- Users
INSERT INTO kavach_user (id, email, name, email_verified, created_at, updated_at)
SELECT
  id,
  email,
  name,
  email_verified,
  created_at,
  updated_at
FROM "user"           -- better-auth default table name
ON CONFLICT (id) DO NOTHING;

-- Accounts (OAuth connections)
INSERT INTO kavach_account (
  id, user_id, provider_id, provider_account_id,
  access_token, refresh_token, expires_at, created_at, updated_at
)
SELECT
  id,
  user_id,
  provider_id,
  account_id,          -- better-auth calls this account_id
  access_token,
  refresh_token,
  expires_at,
  created_at,
  updated_at
FROM account
ON CONFLICT (id) DO NOTHING;

-- Sessions (active sessions)
INSERT INTO kavach_session (
  id, user_id, token, expires_at, ip_address, user_agent, created_at, updated_at
)
SELECT
  id,
  user_id,
  token,
  expires_at,
  ip_address,
  user_agent,
  created_at,
  updated_at
FROM session
ON CONFLICT (id) DO NOTHING;
```

!!! warning
    Column names in better-auth can vary depending on your adapter and any custom fields you added. Run `SELECT column_name FROM information_schema.columns WHERE table_name = 'user'` against your database to confirm the exact names before running the migration.

## Rollout strategy

Keep better-auth running behind a feature flag while you roll out TheAuth to a percentage of traffic:

```ts
// middleware.ts (Next.js)
import { NextRequest, NextResponse } from 'next/server';

export function middleware(req: NextRequest) {
  const userId = req.cookies.get('user_id')?.value ?? '';
  const bucket = hashToPercent(userId);
  const rolloutPercent = Number(process.env.THEAUTH_ROLLOUT ?? '0');

  if (bucket < rolloutPercent) {
    return NextResponse.rewrite(new URL(req.url.replace('/api/auth', '/api/kavach'), req.url));
  }

  return NextResponse.next();
}

function hashToPercent(str: string): number {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    hash = (hash * 31 + str.charCodeAt(i)) >>> 0;
  }
  return hash % 100;
}

export const config = { matcher: '/api/auth/:path*' };
```

Set `THEAUTH_ROLLOUT=10` to start at 10%, then raise it over days as you validate sessions in the TheAuth tables.

## FAQ

**Does TheAuth support all the OAuth providers better-auth has?**
No. As of 2026-04 we ship 17 first-class providers: Apple, Atlassian, Discord, Dropbox, Figma, GitHub, GitLab, Google, LinkedIn, Microsoft, Notion, Reddit, Slack, Spotify, Twitch, Twitter/X, Zoom. Any provider with a standard OAuth 2.0 authorization code flow works via the generic provider factory, but you write the config by hand.

**Is Prisma supported?**
Yes. Install `@glinr/theauth-prisma` and pass a `PrismaClient` as the database backend.

**Do I need to install an MCP plugin?**
No. MCP OAuth 2.1 is built into TheAuth core. Pass a `mcp` config block to `createAuth`.

**Will my users have to sign in again?**
With the `cookieAuth` adapter, no. TheAuth will accept existing better-auth sessions. Without the adapter, existing tokens will be rejected.

## Related pages

- [Compare: vs better-auth](../compare/vs-better-auth.md)
- [Database Setup](../guides/database.md)
- [Agent Identity](../concepts/agents.md)
