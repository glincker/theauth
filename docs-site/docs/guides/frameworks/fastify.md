---
title: Fastify
description: Mount TheAuth auth routes on a Fastify app with authFastify(kavach). Plugins and decorators.
---

# Fastify

`authFastify(kavach, options?)` returns a Fastify plugin. Register it with a prefix.

## Install

```bash
pnpm add @glinr/theauth @glinr/theauth-fastify fastify
```

## Setup

```typescript
import Fastify from 'fastify';
import { createTheAuth, createMcpModule } from '@glinr/theauth';
import { authFastify } from '@glinr/theauth-fastify';

const kavach = createTheAuth({
  database: { provider: 'postgres', url: process.env.DATABASE_URL! },
  baseUrl: process.env.AUTH_BASE_URL!,
});

const mcp = createMcpModule(kavach);

const app = Fastify();

await app.register(authFastify(kavach, { mcp }), { prefix: '/api/kavach' });

await app.listen({ port: 3000 });
```

## Related pages

- [Express](express.md)
- [NestJS](nestjs.md)
- [Adapters Catalog](../../reference/adapters.md)
