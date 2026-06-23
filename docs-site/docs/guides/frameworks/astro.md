---
title: Astro
description: Mount TheAuth auth routes in an Astro app with authAstro(kavach). Returns named handlers for a catch-all API page.
---

# Astro

`authAstro(kavach, options?)` returns named route handlers `{ GET, POST, PATCH, DELETE, OPTIONS, ALL }`. Mount them in a catch-all API page so all TheAuth paths are handled.

## Install

```bash
pnpm add @glinr/theauth @glinr/theauth-astro
```

## Setup

### 1. Create the kavach instance

```typescript
// src/lib/kavach.ts
import { createAuth, createMcpModule } from '@glinr/theauth';

export const kavach = createAuth({
  database: { provider: 'postgres', url: import.meta.env.DATABASE_URL },
  baseUrl: import.meta.env.AUTH_BASE_URL,
  mcp: {
    issuer: import.meta.env.AUTH_BASE_URL,
    audience: import.meta.env.MCP_BASE_URL,
  },
});

export const mcp = createMcpModule(kavach);
```

### 2. Create the catch-all route

Create `src/pages/api/kavach/[...path].ts`. The `[...path]` spread catches every sub-path under `/api/kavach/`.

```typescript
// src/pages/api/kavach/[...path].ts
import type { APIRoute } from 'astro';
import { authAstro } from '@glinr/theauth-astro';
import { kavach, mcp } from '../../../lib/kavach';

const handlers = authAstro(kavach, { mcp });

export const GET: APIRoute = handlers.GET;
export const POST: APIRoute = handlers.POST;
export const PATCH: APIRoute = handlers.PATCH;
export const DELETE: APIRoute = handlers.DELETE;
export const OPTIONS: APIRoute = handlers.OPTIONS;
```

## Related pages

- [Next.js App Router](nextjs.md)
- [Adapters Catalog](../../reference/adapters.md)
