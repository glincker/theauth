---
title: NestJS
description: Wire TheAuth into NestJS with TheAuthModule.forRoot(options). Mounts agent identity, delegation, audit, and MCP OAuth routes as Express middleware in AppModule.
---

# NestJS

`TheAuthModule.forRoot(options)` is a NestJS dynamic module that mounts all TheAuth routes as Express middleware. Import it once in your root `AppModule`.

## Install

```bash
pnpm add @glinr/theauth @glinr/theauth-nestjs
```

## Setup

### 1. Create the theauth instance

```typescript
// lib/theauth.ts
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

### 2. Import TheAuthModule

```typescript
// app.module.ts
import { Module } from '@nestjs/common';
import { TheAuthModule } from '@glinr/theauth-nestjs';
import { theauth, mcp } from './lib/theauth.js';

@Module({
  imports: [
    TheAuthModule.forRoot({
      theauth,
      mcp,
      basePath: '/api/theauth', // default
    }),
  ],
})
export class AppModule {}
```

### 3. Bootstrap

```typescript
// main.ts
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module.js';

const app = await NestFactory.create(AppModule);
await app.listen(3000);
```

## Related pages

- [Express](express.md)
- [Fastify](fastify.md)
- [Adapters Catalog](../../reference/adapters.md)
