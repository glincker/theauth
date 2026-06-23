---
title: Nuxt
description: Mount TheAuth auth routes in Nuxt with authNuxt(kavach). Returns an H3 EventHandler for a catch-all server route.
---

# Nuxt

`authNuxt(kavach, options?)` returns an H3 `EventHandler`. Mount it in a catch-all server route so all TheAuth paths are handled.

## Install

```bash
pnpm add @glinr/theauth @glinr/theauth-nuxt
```

## Setup

### 1. Create the kavach instance

Create this outside the event handler so it is initialized once at server startup:

```typescript
// server/utils/kavach.ts
import { createAuth, createMcpModule } from '@glinr/theauth';

export const kavach = createAuth({
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

```typescript
// server/api/kavach/[...].ts
import { authNuxt } from '@glinr/theauth-nuxt';
import { kavach, mcp } from '~/server/utils/kavach';

export default authNuxt(kavach, { mcp });
```

## Related pages

- [Next.js App Router](nextjs.md)
- [SvelteKit](sveltekit.md)
- [Adapters Catalog](../../reference/adapters.md)
