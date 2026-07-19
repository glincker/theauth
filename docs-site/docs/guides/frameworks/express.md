---
title: Express
description: Mount TheAuth auth routes on an Express app with kavachExpress(kavach).
---

# Express

`kavachExpress(kavach, options?)` returns an Express router. Mount it at your preferred path.

## Install

```bash
pnpm add @glinr/theauth @glinr/theauth-express express
pnpm add -D @types/express
```

## Setup

```typescript
import express from 'express';
import { createTheAuth, createMcpModule } from '@glinr/theauth';
import { kavachExpress } from '@glinr/theauth-express';

const kavach = createTheAuth({
  database: { provider: 'postgres', url: process.env.DATABASE_URL! },
  baseUrl: process.env.AUTH_BASE_URL!,
});

const mcp = createMcpModule(kavach);

const app = express();

app.use('/api/kavach', kavachExpress(kavach, { mcp }));

app.listen(3000, () => {
  console.log('Server running on http://localhost:3000');
});
```

## Related pages

- [Fastify](fastify.md)
- [NestJS](nestjs.md)
- [Adapters Catalog](../../reference/adapters.md)
