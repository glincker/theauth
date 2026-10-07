---
title: Hono
description: Mount TheAuth auth routes on a Hono app with theAuthHono(theauth). Web-standard Request/Response, runs on Workers, Bun, Deno, and Node.
---

# Hono

`theAuthHono(theauth, options?)` returns a `Hono` app instance with all TheAuth routes pre-mounted. Use `app.route` to attach it to your main app.

## Install

```bash
pnpm add @glinr/theauth @glinr/theauth-hono hono @hono/node-server
```

## Setup

### 1. Create the theauth instance

```typescript
// lib/theauth.ts
import { createTheAuth, createMcpModule } from '@glinr/theauth';

export const theauth = createTheAuth({
  database: { provider: 'sqlite', url: 'theauth.db' },
  baseUrl: process.env.AUTH_BASE_URL!,
  mcp: {
    issuer: process.env.AUTH_BASE_URL!,
    audience: process.env.MCP_BASE_URL!,
  },
});

export const mcp = createMcpModule(theauth);
```

### 2. Mount the adapter

```typescript
// src/index.ts
import { Hono } from 'hono';
import { theAuthHono } from '@glinr/theauth-hono';
import { theauth, mcp } from './lib/theauth';

const app = new Hono();

app.route('/api/theauth', theAuthHono(theauth, { mcp }));

export default app;
```

## Cloudflare Workers

Pass a D1 binding from the Worker environment:

```typescript
import { createTheAuth } from '@glinr/theauth';
import { theAuthHono } from '@glinr/theauth-hono';
import { Hono } from 'hono';

type Env = { THEAUTH_DB: D1Database };

const app = new Hono<{ Bindings: Env }>();

app.use('/api/theauth/*', async (c, next) => {
  const theauth = createTheAuth({
    database: { provider: 'd1', binding: c.env.THEAUTH_DB },
    baseUrl: 'https://auth.example.com',
  });
  c.set('theauth', theauth);
  await next();
});

// Or initialize once outside the handler with a module Worker pattern
export default app;
```

## Related pages

- [Next.js App Router](nextjs.md)
- [SvelteKit](sveltekit.md)
- [Adapters Catalog](../../reference/adapters.md)
