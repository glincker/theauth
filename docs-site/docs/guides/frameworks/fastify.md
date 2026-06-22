---
title: Fastify
description: Mount TheAuth auth routes on a Fastify app with kavachFastify(kavach). Plugins and decorators.
---

# Fastify

`kavachFastify(kavach, options?)` returns a Fastify plugin. Register it with a prefix.

## Install

```bash
pnpm add @glinr/theauth @glinr/theauth-fastify fastify
```

## Setup

```typescript
import Fastify from 'fastify';
import { createKavach, createMcpModule } from '@glinr/theauth';
import { kavachFastify } from '@glinr/theauth-fastify';

const kavach = createKavach({
  database: { provider: 'postgres', url: process.env.DATABASE_URL! },
  baseUrl: process.env.AUTH_BASE_URL!,
});

const mcp = createMcpModule(kavach);

const app = Fastify();

await app.register(kavachFastify(kavach, { mcp }), { prefix: '/api/kavach' });

await app.listen({ port: 3000 });
```

## Related pages

- [Express](express.md)
- [NestJS](nestjs.md)
- [Adapters Catalog](../../reference/adapters.md)
