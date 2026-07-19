---
title: Quick Start
description: Install TheAuth, create your first AgentIdentity, and run an authorization check. Six steps.
---

# Quick Start

Two paths. Pick whichever fits your day.

- **Start from a template**: one command, a running Next.js SaaS, TheAuth wired up.
- **Add to an existing app**: install, create, authorize, audit. Six steps.

## Start from a template

=== "pnpm"
    ```bash
    pnpm create theauth-app
    ```
=== "npm"
    ```bash
    npm create theauth-app
    ```
=== "yarn"
    ```bash
    yarn create theauth-app
    ```
=== "bun"
    ```bash
    bun create theauth-app
    ```

The CLI asks for a directory, a template, a package manager, and a database driver. Only the Next.js SaaS template is shipping today; the Hono MCP and Expo templates print a coming-soon note and exit.

Next steps are printed at the end: `cd`, install, `db:push`, `dev`.

## Add to an existing app

### 1. Install

=== "pnpm"
    ```bash
    pnpm add @glinr/theauth
    ```
=== "npm"
    ```bash
    npm install @glinr/theauth
    ```
=== "yarn"
    ```bash
    yarn add @glinr/theauth
    ```

### 2. Create an instance

Pass a database config to `createTheAuth`. Use SQLite for local development and Postgres in production.

```ts
import { createTheAuth } from '@glinr/theauth';

const kavach = createTheAuth({
  database: { provider: 'sqlite', url: 'kavach.db' },
  agents: {
    enabled: true,
    maxPerUser: 10,
    auditAll: true,    // record every authorize() call
    tokenExpiry: '24h',
  },
});
```

!!! info
    For in-memory storage (useful in tests), pass `url: ':memory:'` instead.

### 3. Create an agent

An agent always has an owner: the user ID from your existing auth system. TheAuth does not manage human authentication.

```ts
const agent = await kavach.agent.create({
  ownerId: 'user-123',          // from your auth provider
  name: 'github-reader',
  type: 'autonomous',
  permissions: [
    {
      resource: 'mcp:github:*',
      actions: ['read'],
    },
    {
      resource: 'mcp:deploy:production',
      actions: ['execute'],
      constraints: {
        requireApproval: true,   // human-in-the-loop gate
        maxCallsPerHour: 5,
      },
    },
  ],
});

// agent.token is the bearer token: "kv_..."
console.log(agent.token);
```

!!! warning
    The token is shown exactly once, at creation time. Store it immediately in your secrets manager or pass it directly to the agent. It cannot be recovered after this point, only rotated.

Three agent types are available:

| Type | When to use |
|---|---|
| `autonomous` | Runs without human involvement. Default for most agents. |
| `delegated` | Receives permissions from another agent via a delegation chain. |
| `service` | Long-lived service account identity. |

### 4. Authorize an action

Call `kavach.authorize` before any sensitive operation. It returns `{ allowed, reason?, auditId }`.

```ts
const result = await kavach.authorize(agent.id, {
  action: 'read',
  resource: 'mcp:github:repos',
});

if (!result.allowed) {
  throw new Error(`Denied: ${result.reason}`);
}

// result.auditId links this decision to its audit log entry
```

If you only have the raw bearer token (from an incoming HTTP request, for example), use `authorizeByToken` instead:

```ts
const result = await kavach.authorizeByToken(bearerToken, {
  action: 'read',
  resource: 'mcp:github:repos',
});
```

### 5. Check the audit trail

Every authorization decision is logged. Query by agent, filter by result, or export for compliance.

```ts
// All decisions for an agent
const logs = await kavach.audit.query({ agentId: agent.id });

// Only the denials
const denied = await kavach.audit.query({
  agentId: agent.id,
  result: 'denied',
});

// Export everything as CSV
const csv = await kavach.audit.export({ format: 'csv' });
```

## Delegation

An orchestrator agent can delegate a subset of its permissions to a sub-agent. The delegation has its own expiry and a `maxDepth` to prevent unbounded chains.

```ts
const sub = await kavach.agent.create({
  ownerId: 'user-123',
  name: 'sub-reader',
  type: 'delegated',
  permissions: [],  // starts empty; receives permissions via delegation
});

await kavach.delegate({
  fromAgent: agent.id,
  toAgent: sub.id,
  permissions: [{ resource: 'mcp:github:issues', actions: ['read'] }],
  expiresAt: new Date(Date.now() + 3_600_000),  // 1 hour
  maxDepth: 2,
});

// Resolves the full effective permission set, including delegated ones
const perms = await kavach.delegation.getEffectivePermissions(sub.id);
```

!!! info
    An agent cannot delegate permissions it does not hold itself. Attempts to escalate are rejected at the point of delegation, not at authorization time.

## Cloudflare Workers

TheAuth runs on Workers with no changes. Pass a D1 binding as the database and use the Hono adapter.

```typescript
import { createTheAuth } from '@glinr/theauth';
import { Hono } from 'hono';

type Env = { KAVACH_DB: D1Database };

const app = new Hono<{ Bindings: Env }>();

app.get('/health', async (c) => {
  const kavach = await createTheAuth({
    database: { provider: 'd1', binding: c.env.KAVACH_DB },
  });

  const agent = await kavach.agent.create({
    ownerId: 'user-1',
    name: 'my-agent',
    type: 'autonomous',
    permissions: [{ resource: 'mcp:github:*', actions: ['read'] }],
  });

  return c.json({ agent });
});

export default app;
```

Bind a D1 database in your `wrangler.toml`:

```toml
[[d1_databases]]
binding = "KAVACH_DB"
database_name = "kavach"
database_id = "<your-database-id>"
```

## Troubleshooting

### "Invalid email or password" after sign-up

Sign-in requires email verification by default. Either verify the email using the token from the sign-up response, or set `requireVerification: false` in the `emailPassword()` config.

### "FOREIGN KEY constraint failed" when creating agents

You need a user in the `kavach_users` table before creating agents. Sign up via the email auth plugin, or seed a user manually:

```typescript
kavach.db.insert(users).values({
  id: 'user-1',
  email: 'test@example.com',
  name: 'Test',
  createdAt: new Date(),
  updatedAt: new Date(),
}).run();
```

### Session not persisting after page reload

The React hooks store sessions in `localStorage`. Make sure your app is wrapped in `<TheAuthProvider>`. If using SSR (Next.js), wrap the provider in a `"use client"` component.

## Next steps

- [Permission engine](../guides/permissions.md) - Wildcards, rate limits, time windows, IP allowlists, approval gates.
- [Delegation chains](../concepts/delegation.md) - Sub-agent delegation with depth limits and cascading revocation.
- [MCP OAuth 2.1](../concepts/mcp-authorization.md) - Set up the authorization server for MCP tool servers.
- [Framework adapters](../reference/adapters.md) - Drop-in middleware for ten frameworks.
- [Migration guides](../migrations/overview.md) - Coming from another library.
- [Configuration](../reference/configuration.md) - All `createTheAuth()` options.
