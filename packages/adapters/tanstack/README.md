# @glinr/theauth-tanstack

[npm](https://www.npmjs.com/package/@glinr/theauth-tanstack) · [Source](https://github.com/glincker/theauth/tree/main/packages/adapters/tanstack) · [Docs](https://docs.theauth.dev/adapters/tanstack) · [All packages](https://github.com/glincker/theauth#packages)

TanStack Start adapter for theAuth.

[![npm](https://img.shields.io/npm/v/@glinr/theauth-tanstack?style=flat-square)](https://www.npmjs.com/package/@glinr/theauth-tanstack)

Part of [theAuth](https://theauth.dev), open-source auth for AI agents and humans. Docs: [docs.theauth.dev](https://docs.theauth.dev).

## Install

```bash
npm install @glinr/theauth @glinr/theauth-tanstack
```

## Usage

```typescript
import { createTheAuth } from "@glinr/theauth";
import { theAuthTanStack } from "@glinr/theauth-tanstack";

const theauth = createTheAuth({
  database: { provider: "sqlite", url: "theauth.db" },
});

// Mount in your TanStack Start API routes
export const { GET, POST } = theAuthTanStack(theauth, { authenticate });
```

## Management routes and client IP

With the default session guard, a signed-in user only acts on their own agents, delegations and audit rows. A custom `authenticate` resolver is a trust decision and sees everything.

The adapter does not read forwarded headers for the client IP. Behind a proxy, set `trustedProxy` with `trustedProxyCount` or `trustedHeader`, or `ipAllowlist` constraints cannot match.

```ts
const handlers = theAuthTanStack(theauth, { authenticate, trustedProxy: { trustedProxyCount: 1 } });
```

On Cloudflare use `trustedHeader: "cf-connecting-ip"`. Only trust a header your edge overwrites.

## Docs

[docs.theauth.dev/adapters/tanstack](https://docs.theauth.dev/adapters/tanstack)

## License

MIT
