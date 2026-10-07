# @glinr/theauth-solidstart

SolidStart adapter for TheAuth.

[![npm](https://img.shields.io/npm/v/@glinr/theauth-solidstart?style=flat-square)](https://www.npmjs.com/package/@glinr/theauth-solidstart)

## Install

```bash
npm install @glinr/theauth @glinr/theauth-solidstart
```

## Usage

```typescript
import { createTheAuth } from "@glinr/theauth";
import { theAuthSolidStart } from "@glinr/theauth-solidstart";

const theauth = createTheAuth({
  database: { provider: "sqlite", url: "theauth.db" },
});

// Mount in your SolidStart API routes
export const { GET, POST } = theAuthSolidStart(theauth);
```

## Docs

[docs.theauth.dev/docs/adapters/solidstart](https://docs.theauth.dev/docs/adapters/solidstart)

## License

MIT
