---
title: SvelteKit
description: Mount TheAuth auth routes in SvelteKit with authSvelteKit(theauth). Returns named server route handlers, fully edge-compatible with no conversion layer.
---

# SvelteKit

`authSvelteKit(theauth, options?)` returns named route handlers `{ GET, POST, PATCH, DELETE, OPTIONS }`. Mount them in a catch-all server route file so all TheAuth paths are handled.

## Install

```bash
pnpm add @glinr/theauth @glinr/theauth-sveltekit
```

## Setup

### 1. Create the theauth instance

```typescript
// src/lib/theauth.ts
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

Create `src/routes/api/theauth/[...path]/+server.ts`. The `[...path]` segment catches every sub-path.

```typescript
// src/routes/api/theauth/[...path]/+server.ts
import { authSvelteKit } from '@glinr/theauth-sveltekit';
import { theauth, mcp } from '$lib/theauth';

const handlers = authSvelteKit(theauth, { mcp });

export const GET = handlers.GET;
export const POST = handlers.POST;
export const PATCH = handlers.PATCH;
export const DELETE = handlers.DELETE;
export const OPTIONS = handlers.OPTIONS;
```

## Edge compatibility

The SvelteKit adapter is fully edge-compatible. To deploy on Cloudflare Workers or Vercel Edge, add the edge adapter to your SvelteKit config and ensure you use the `d1` or another edge-compatible database provider.

## Related pages

- [Next.js App Router](nextjs.md)
- [Hono](hono.md)
- [Adapters Catalog](../../reference/adapters.md)
