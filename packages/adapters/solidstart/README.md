# @glinr/theauth-solidstart

SolidStart adapter for theAuth.

[![npm](https://img.shields.io/npm/v/@glinr/theauth-solidstart?style=flat-square)](https://www.npmjs.com/package/@glinr/theauth-solidstart)

Part of [theAuth](https://theauth.dev), open-source auth for AI agents and humans. Docs: [docs.theauth.dev](https://docs.theauth.dev).

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

[docs.theauth.dev/adapters/solidstart](https://docs.theauth.dev/adapters/solidstart)

## License

MIT
