---
title: Next.js App Router
description: Mount TheAuth auth routes in Next.js with authNextjs(theauth). Drop into a catch-all App Router file for agent identity, delegation, and MCP OAuth 2.1 endpoints.
---

# Next.js App Router

`authNextjs(theauth, options?)` returns named route handlers `{ GET, POST, PATCH, DELETE, OPTIONS }` for the Next.js App Router. Mount them in a catch-all route file so all TheAuth paths are handled.

## Install

```bash
pnpm add @glinr/theauth @glinr/theauth-nextjs
```

## Setup

### 1. Create the theauth instance

Create this in a shared module so it is initialized once at server startup:

```typescript
// lib/theauth.ts
import { createTheAuth, createMcpModule } from '@glinr/theauth';

export const theauth = createTheAuth({
  database: { provider: 'postgres', url: process.env.DATABASE_URL! },
  baseUrl: process.env.AUTH_BASE_URL!,
  mcp: {
    issuer: process.env.AUTH_BASE_URL!,
    audience: process.env.MCP_BASE_URL!,
  },
});

export const mcp = createMcpModule(theauth);
```

### 2. Create the catch-all route

Create `app/api/theauth/[...theauth]/route.ts`. The `[...theauth]` segment catches every sub-path under `/api/theauth/`.

```typescript
// app/api/theauth/[...theauth]/route.ts
import { authNextjs } from '@glinr/theauth-nextjs';
import { theauth, mcp } from '@/lib/theauth';

const handlers = authNextjs(theauth, { mcp });

export const GET = handlers.GET;
export const POST = handlers.POST;
export const PATCH = handlers.PATCH;
export const DELETE = handlers.DELETE;
export const OPTIONS = handlers.OPTIONS;
```

## MCP endpoints

When `mcp` is passed, the following endpoints are available:

```
GET  /api/theauth/.well-known/oauth-authorization-server
GET  /api/theauth/.well-known/oauth-protected-resource
POST /api/theauth/mcp/register
GET  /api/theauth/mcp/authorize
POST /api/theauth/mcp/token
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
// app/api/theauth/[...theauth]/route.ts
import { createTheAuth, createMcpModule } from '@glinr/theauth';
import { authNextjs } from '@glinr/theauth-nextjs';

const theauth = createTheAuth({
  database: { provider: 'postgres', url: process.env.DATABASE_URL! },
  baseUrl: process.env.AUTH_BASE_URL!,
  mcp: {
    issuer: process.env.AUTH_BASE_URL!,
    audience: process.env.MCP_BASE_URL!,
  },
});

const mcp = createMcpModule(theauth);

const handlers = authNextjs(theauth, { mcp });

export const GET = handlers.GET;
export const POST = handlers.POST;
export const PATCH = handlers.PATCH;
export const DELETE = handlers.DELETE;
export const OPTIONS = handlers.OPTIONS;
```

!!! warning
    Do not define `createTheAuth` inside the route file if you need the instance elsewhere in your app. Export it from `lib/theauth.ts` and import it where needed to avoid creating multiple instances.

## Related pages

- [SvelteKit](sveltekit.md)
- [Hono](hono.md)
- [MCP Authorization](../../concepts/mcp-authorization.md)
- [Adapters Catalog](../../reference/adapters.md)
