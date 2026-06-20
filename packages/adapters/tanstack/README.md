# @theauth/tanstack

TanStack Start adapter for TheAuth.

[![npm](https://img.shields.io/npm/v/@theauth/tanstack?style=flat-square)](https://www.npmjs.com/package/@theauth/tanstack)

## Install

```bash
npm install theauth @theauth/tanstack
```

## Usage

```typescript
import { createKavach } from "theauth";
import { kavachTanStack } from "@theauth/tanstack";

const kavach = createKavach({
  database: { provider: "sqlite", url: "kavach.db" },
});

// Mount in your TanStack Start API routes
export const { GET, POST } = kavachTanStack(kavach);
```

## Docs

[docs.theauth.com/docs/adapters/tanstack](https://docs.theauth.com/docs/adapters/tanstack)

## License

MIT
