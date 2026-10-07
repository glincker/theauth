---
title: Fastify
description: Mount TheAuth auth routes on a Fastify app with authFastify(theauth). Plugins and decorators.
---

# Fastify

`authFastify(theauth, options?)` returns a Fastify plugin. Register it with a prefix.

## Install

```bash
pnpm add @glinr/theauth @glinr/theauth-fastify fastify
```

## Setup

```typescript
import Fastify from 'fastify';
import { createTheAuth, createMcpModule } from '@glinr/theauth';
import { authFastify } from '@glinr/theauth-fastify';

const theauth = createTheAuth({
  database: { provider: 'postgres', url: process.env.DATABASE_URL! },
  baseUrl: process.env.AUTH_BASE_URL!,
});

const mcp = createMcpModule(theauth);

const app = Fastify();

await app.register(authFastify(theauth, { mcp }), { prefix: '/api/theauth' });

await app.listen({ port: 3000 });
```

## Related pages

- [Express](express.md)
- [NestJS](nestjs.md)
- [Adapters Catalog](../../reference/adapters.md)
