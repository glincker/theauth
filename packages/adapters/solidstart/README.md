# @glinr/theauth-solidstart

[npm](https://www.npmjs.com/package/@glinr/theauth-solidstart) · [Source](https://github.com/glincker/theauth/tree/main/packages/adapters/solidstart) · [Docs](https://docs.theauth.dev/adapters/solidstart) · [All packages](https://github.com/glincker/theauth#packages)

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
export const { GET, POST } = theAuthSolidStart(theauth, { authenticate });
```

## Management routes and client IP

With the default session guard, a signed-in user only acts on their own agents, delegations and audit rows. A custom `authenticate` resolver is a trust decision and sees everything.

The adapter does not read forwarded headers for the client IP. Behind a proxy, set `trustedProxy` with `trustedProxyCount` or `trustedHeader`, or `ipAllowlist` constraints cannot match.

```ts
const handlers = theAuthSolidStart(theauth, { authenticate, trustedProxy: { trustedProxyCount: 1 } });
```

On Cloudflare use `trustedHeader: "cf-connecting-ip"`. Only trust a header your edge overwrites.

## Docs

[docs.theauth.dev/adapters/solidstart](https://docs.theauth.dev/adapters/solidstart)

## License

MIT
