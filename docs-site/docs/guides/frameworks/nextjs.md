---
title: Next.js App Router
description: Mount TheAuth auth routes in Next.js with kavachNextjs(kavach). Drop into a catch-all App Router file for agent identity, delegation, and MCP OAuth 2.1 endpoints.
---

# Next.js App Router

`kavachNextjs(kavach, options?)` returns named route handlers `{ GET, POST, PATCH, DELETE, OPTIONS }` for the Next.js App Router. Mount them in a catch-all route file so all TheAuth paths are handled.

## Install

```bash
pnpm add @glinr/theauth @glinr/theauth-nextjs
```

## Setup

### 1. Create the kavach instance

Create this in a shared module so it is initialized once at server startup:

```typescript
// lib/kavach.ts
import { createKavach, createMcpModule } from '@glinr/theauth';

export const kavach = createKavach({
  database: { provider: 'postgres', url: process.env.DATABASE_URL! },
  baseUrl: process.env.AUTH_BASE_URL!,
  mcp: {
    issuer: process.env.AUTH_BASE_URL!,
    audience: process.env.MCP_BASE_URL!,
  },
});

export const mcp = createMcpModule(kavach);
```

### 2. Create the catch-all route

Create `app/api/kavach/[...kavach]/route.ts`. The `[...kavach]` segment catches every sub-path under `/api/kavach/`.

```typescript
// app/api/kavach/[...kavach]/route.ts
import { kavachNextjs } from '@glinr/theauth-nextjs';
import { kavach, mcp } from '@/lib/kavach';

const handlers = kavachNextjs(kavach, { mcp });

export const GET = handlers.GET;
export const POST = handlers.POST;
export const PATCH = handlers.PATCH;
export const DELETE = handlers.DELETE;
export const OPTIONS = handlers.OPTIONS;
```

## MCP endpoints

When `mcp` is passed, the following endpoints are available:

```
GET  /api/kavach/.well-known/oauth-authorization-server
GET  /api/kavach/.well-known/oauth-protected-resource
POST /api/kavach/mcp/register
GET  /api/kavach/mcp/authorize
POST /api/kavach/mcp/token
```

## Endpoint reference

| Method | Path | Description |
|---|---|---|
| `POST` | `/agents` | Create an agent |
| `GET` | `/agents` | List agents |
| `GET` | `/agents/:id` | Get an agent |
| `PATCH` | `/agents/:id` | Update an agent |
| `DELETE` | `/agents/:id` | Revoke an agent |
| `POST` | `/agents/:id/rotate` | Rotate token |
| `POST` | `/authorize` | Authorize by agent ID |
| `POST` | `/authorize/token` | Authorize by bearer token |
| `POST` | `/delegations` | Create delegation |
| `GET` | `/delegations/:agentId` | List delegation chains |
| `DELETE` | `/delegations/:id` | Revoke delegation |
| `GET` | `/audit` | Query audit logs |
| `GET` | `/audit/export` | Export audit logs |

## Full example

```typescript
// app/api/kavach/[...kavach]/route.ts
import { createKavach, createMcpModule } from '@glinr/theauth';
import { kavachNextjs } from '@glinr/theauth-nextjs';

const kavach = createKavach({
  database: { provider: 'postgres', url: process.env.DATABASE_URL! },
  baseUrl: process.env.AUTH_BASE_URL!,
  mcp: {
    issuer: process.env.AUTH_BASE_URL!,
    audience: process.env.MCP_BASE_URL!,
  },
});

const mcp = createMcpModule(kavach);

const handlers = kavachNextjs(kavach, { mcp });

export const GET = handlers.GET;
export const POST = handlers.POST;
export const PATCH = handlers.PATCH;
export const DELETE = handlers.DELETE;
export const OPTIONS = handlers.OPTIONS;
```

!!! warning
    Do not define `createKavach` inside the route file if you need the instance elsewhere in your app. Export it from `lib/kavach.ts` and import it where needed to avoid creating multiple instances.

## Related pages

- [SvelteKit](sveltekit.md)
- [Hono](hono.md)
- [MCP Authorization](../../concepts/mcp-authorization.md)
- [Adapters Catalog](../../reference/adapters.md)
