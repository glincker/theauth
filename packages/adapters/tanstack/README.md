# @kavachos/tanstack

TanStack Start adapter for KavachOS.

[![npm](https://img.shields.io/npm/v/@kavachos/tanstack?style=flat-square)](https://www.npmjs.com/package/@kavachos/tanstack)

## Install

```bash
npm install kavachos @kavachos/tanstack
```

## Usage

```typescript
import { createKavach } from "kavachos";
import { kavachTanStack } from "@kavachos/tanstack";

const kavach = createKavach({
  database: { provider: "sqlite", url: "kavach.db" },
});

// Mount in your TanStack Start API routes
export const { GET, POST } = kavachTanStack(kavach);
```

## Docs

[docs.kavachos.com/docs/adapters/tanstack](https://docs.kavachos.com/docs/adapters/tanstack)

## License

MIT
