# @kavachos/prisma

Prisma database adapter for KavachOS. Use PrismaClient as your KavachOS database backend.

[![npm](https://img.shields.io/npm/v/@kavachos/prisma?style=flat-square)](https://www.npmjs.com/package/@kavachos/prisma)

## Install

```bash
npm install kavachos @kavachos/prisma @prisma/client
```

## Usage

```typescript
import { createKavach } from "kavachos";
import { PrismaClient } from "@prisma/client";
import { kavachPrisma } from "@kavachos/prisma";

const prisma = new PrismaClient();

const kavach = createKavach({
  database: kavachPrisma(prisma),
});
```

## When to use

Use this adapter if your app already uses Prisma and you want KavachOS to share the same database connection and transaction context. For new projects, the built-in database providers (`sqlite`, `postgres`, `mysql`, `d1`) are simpler.

## Docs

[docs.kavachos.com/docs/adapters/prisma](https://docs.kavachos.com/docs/adapters/prisma)

## License

MIT
