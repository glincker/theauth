# @glinr/theauth-solidstart

SolidStart adapter for TheAuth.

[![npm](https://img.shields.io/npm/v/@glinr/theauth-solidstart?style=flat-square)](https://www.npmjs.com/package/@glinr/theauth-solidstart)

## Install

```bash
npm install theauth @glinr/@glinr/theauth-solidstart
```

## Usage

```typescript
import { createKavach } from "@glinr/theauth";
import { kavachSolidStart } from "@glinr/theauth-solidstart";

const kavach = createKavach({
  database: { provider: "sqlite", url: "kavach.db" },
});

// Mount in your SolidStart API routes
export const { GET, POST } = kavachSolidStart(kavach);
```

## Docs

[docs.theauth.com/docs/adapters/solidstart](https://docs.theauth.com/docs/adapters/solidstart)

## License

MIT
