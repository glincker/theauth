---
title: Nuxt
description: Mount TheAuth auth routes in Nuxt with authNuxt(theauth). Returns an H3 EventHandler for a catch-all server route.
---

# Nuxt

`authNuxt(theauth, options?)` returns an H3 `EventHandler`. Mount it in a catch-all server route so all TheAuth paths are handled.

## Install

```bash
pnpm add @glinr/theauth @glinr/theauth-nuxt
```

## Setup

### 1. Create the theauth instance

Create this outside the event handler so it is initialized once at server startup:

```typescript
// server/utils/theauth.ts
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

```typescript
// server/api/theauth/[...].ts
import { authNuxt } from '@glinr/theauth-nuxt';
import { theauth, mcp } from '~/server/utils/theauth';

export default authNuxt(theauth, { mcp });
```

## Related pages

- [Next.js App Router](nextjs.md)
- [SvelteKit](sveltekit.md)
- [Adapters Catalog](../../reference/adapters.md)
