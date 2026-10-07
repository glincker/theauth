# @glinr/theauth-prisma

[npm](https://www.npmjs.com/package/@glinr/theauth-prisma) · [Source](https://github.com/glincker/theauth/tree/main/packages/adapters/prisma) · [Docs](https://docs.theauth.dev/prisma) · [All packages](https://github.com/glincker/theauth#packages)

Prisma database adapter for theAuth. Use PrismaClient as your theAuth database backend.

[![npm](https://img.shields.io/npm/v/@glinr/theauth-prisma?style=flat-square)](https://www.npmjs.com/package/@glinr/theauth-prisma)

Part of [theAuth](https://theauth.dev), open-source auth for AI agents and humans. Docs: [docs.theauth.dev](https://docs.theauth.dev).

## Install

```bash
npm install @glinr/theauth @glinr/theauth-prisma @prisma/client
```

## Usage

```typescript
import { createTheAuth } from "@glinr/theauth";
import { PrismaClient } from "@prisma/client";
import { theAuthPrisma } from "@glinr/theauth-prisma";

const prisma = new PrismaClient();

const theauth = createTheAuth({
  database: theAuthPrisma(prisma),
});
```

## When to use

Use this adapter if your app already uses Prisma and you want theAuth to share the same database connection and transaction context. For new projects, the built-in database providers (`sqlite`, `postgres`, `mysql`, `d1`) are simpler.

## Docs

[docs.theauth.dev/prisma](https://docs.theauth.dev/prisma)

## License

MIT
