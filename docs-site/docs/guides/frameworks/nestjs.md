---
title: NestJS
description: Wire TheAuth into NestJS with AuthModule.forRoot(options). Mounts agent identity, delegation, audit, and MCP OAuth routes as Express middleware in AppModule.
---

# NestJS

`AuthModule.forRoot(options)` is a NestJS dynamic module that mounts all TheAuth routes as Express middleware. Import it once in your root `AppModule`.

## Install

```bash
pnpm add @glinr/theauth @glinr/theauth-nestjs
```

## Setup

### 1. Create the kavach instance

```typescript
// lib/kavach.ts
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

### 2. Import AuthModule

```typescript
// app.module.ts
import { Module } from '@nestjs/common';
import { AuthModule } from '@glinr/theauth-nestjs';
import { kavach, mcp } from './lib/kavach.js';

@Module({
  imports: [
    AuthModule.forRoot({
      kavach,
      mcp,
      basePath: '/api/kavach', // default
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
