# @glinr/theauth-prisma

Prisma database adapter for TheAuth. Use PrismaClient as your TheAuth database backend.

[![npm](https://img.shields.io/npm/v/@glinr/theauth-prisma?style=flat-square)](https://www.npmjs.com/package/@glinr/theauth-prisma)

## Install

```bash
npm install theauth @glinr/@glinr/theauth-prisma @prisma/client
```

## Usage

```typescript
import { createKavach } from "@glinr/theauth";
import { PrismaClient } from "@prisma/client";
import { kavachPrisma } from "@glinr/theauth-prisma";

const prisma = new PrismaClient();

const kavach = createKavach({
  database: kavachPrisma(prisma),
});
```

## When to use

Use this adapter if your app already uses Prisma and you want TheAuth to share the same database connection and transaction context. For new projects, the built-in database providers (`sqlite`, `postgres`, `mysql`, `d1`) are simpler.

## Docs

[docs.theauth.dev/docs/adapters/prisma](https://docs.theauth.dev/docs/adapters/prisma)

## License

MIT
