# @kavachos/solidstart

SolidStart adapter for KavachOS.

[![npm](https://img.shields.io/npm/v/@kavachos/solidstart?style=flat-square)](https://www.npmjs.com/package/@kavachos/solidstart)

## Install

```bash
npm install kavachos @kavachos/solidstart
```

## Usage

```typescript
import { createKavach } from "kavachos";
import { kavachSolidStart } from "@kavachos/solidstart";

const kavach = createKavach({
  database: { provider: "sqlite", url: "kavach.db" },
});

// Mount in your SolidStart API routes
export const { GET, POST } = kavachSolidStart(kavach);
```

## Docs

[docs.kavachos.com/docs/adapters/solidstart](https://docs.kavachos.com/docs/adapters/solidstart)

## License

MIT
