---
title: Hono
description: Mount TheAuth auth routes on a Hono app with kavachHono(kavach). Web-standard Request/Response, runs on Workers, Bun, Deno, and Node.
---

# Hono

`kavachHono(kavach, options?)` returns a `Hono` app instance with all TheAuth routes pre-mounted. Use `app.route` to attach it to your main app.

## Install

```bash
pnpm add @glinr/theauth @glinr/theauth-hono hono @hono/node-server
```

## Setup

### 1. Create the kavach instance

```typescript
// lib/kavach.ts
import { createKavach, createMcpModule } from '@glinr/theauth';

export const kavach = createKavach({
  database: { provider: 'sqlite', url: 'kavach.db' },
  baseUrl: process.env.AUTH_BASE_URL!,
  mcp: {
    issuer: process.env.AUTH_BASE_URL!,
    audience: process.env.MCP_BASE_URL!,
  },
});

export const mcp = createMcpModule(kavach);
```

### 2. Mount the adapter

```typescript
// src/index.ts
import { Hono } from 'hono';
import { kavachHono } from '@glinr/theauth-hono';
import { kavach, mcp } from './lib/kavach';

const app = new Hono();

app.route('/api/kavach', kavachHono(kavach, { mcp }));

export default app;
```

## Cloudflare Workers

Pass a D1 binding from the Worker environment:

```typescript
import { createKavach } from '@glinr/theauth';
import { kavachHono } from '@glinr/theauth-hono';
import { Hono } from 'hono';

type Env = { KAVACH_DB: D1Database };

const app = new Hono<{ Bindings: Env }>();

app.use('/api/kavach/*', async (c, next) => {
  const kavach = createKavach({
    database: { provider: 'd1', binding: c.env.KAVACH_DB },
    baseUrl: 'https://auth.example.com',
  });
  c.set('kavach', kavach);
  await next();
});

// Or initialize once outside the handler with a module Worker pattern
export default app;
```

## Related pages

- [Next.js App Router](nextjs.md)
- [SvelteKit](sveltekit.md)
- [Adapters Catalog](../../reference/adapters.md)
