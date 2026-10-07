# @glinr/theauth-tanstack

TanStack Start adapter for TheAuth.

[![npm](https://img.shields.io/npm/v/@glinr/theauth-tanstack?style=flat-square)](https://www.npmjs.com/package/@glinr/theauth-tanstack)

## Install

```bash
npm install theauth @glinr/@glinr/theauth-tanstack
```

## Usage

```typescript
import { createTheAuth } from "@glinr/theauth";
import { theAuthTanStack } from "@glinr/theauth-tanstack";

const theauth = createTheAuth({
  database: { provider: "sqlite", url: "theauth.db" },
});

// Mount in your TanStack Start API routes
export const { GET, POST } = theAuthTanStack(theauth);
```

## Docs

[docs.theauth.dev/docs/adapters/tanstack](https://docs.theauth.dev/docs/adapters/tanstack)

## License

MIT
