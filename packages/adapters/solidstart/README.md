# @theauth/solidstart

SolidStart adapter for TheAuth.

[![npm](https://img.shields.io/npm/v/@theauth/solidstart?style=flat-square)](https://www.npmjs.com/package/@theauth/solidstart)

## Install

```bash
npm install theauth @theauth/solidstart
```

## Usage

```typescript
import { createKavach } from "theauth";
import { kavachSolidStart } from "@theauth/solidstart";

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
