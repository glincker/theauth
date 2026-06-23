# @glinr/theauth-tanstack

TanStack Start adapter for TheAuth.

[![npm](https://img.shields.io/npm/v/@glinr/theauth-tanstack?style=flat-square)](https://www.npmjs.com/package/@glinr/theauth-tanstack)

## Install

```bash
npm install theauth @glinr/@glinr/theauth-tanstack
```

## Usage

```typescript
import { createKavach } from "@glinr/theauth";
import { kavachTanStack } from "@glinr/theauth-tanstack";

const kavach = createKavach({
  database: { provider: "sqlite", url: "kavach.db" },
});

// Mount in your TanStack Start API routes
export const { GET, POST } = kavachTanStack(kavach);
```

## Docs

[docs.theauth.dev/docs/adapters/tanstack](https://docs.theauth.dev/docs/adapters/tanstack)

## License

MIT
