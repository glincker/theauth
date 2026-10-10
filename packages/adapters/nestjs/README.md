# @glinr/theauth-nestjs

[npm](https://www.npmjs.com/package/@glinr/theauth-nestjs) · [Source](https://github.com/glincker/theauth/tree/main/packages/adapters/nestjs) · [Docs](https://docs.theauth.dev/adapters/nestjs) · [All packages](https://github.com/glincker/theauth#packages)

NestJS adapter for theAuth.

[![npm](https://img.shields.io/npm/v/@glinr/theauth-nestjs?style=flat-square)](https://www.npmjs.com/package/@glinr/theauth-nestjs)

Part of [theAuth](https://theauth.dev), open-source auth for AI agents and humans. Docs: [docs.theauth.dev](https://docs.theauth.dev).

## Install

```bash
npm install @glinr/theauth @glinr/theauth-nestjs
```

## Usage

### Module import

```typescript
import { Module } from "@nestjs/common";
import { TheAuthModule } from "@glinr/theauth-nestjs";

@Module({
  imports: [
    TheAuthModule.forRoot({
      theauth,
      // Required: who may call /agents, /audit and the other management routes.
      authenticate: async (req) => (await theauth.auth.resolveUser(req)) ?? null,
    }),
  ],
})
export class AppModule {}
```

### Middleware

```typescript
import { createTheAuth } from "@glinr/theauth";
import { theAuthMiddleware } from "@glinr/theauth-nestjs";

const theauth = createTheAuth({
  database: { provider: "postgres", url: process.env.DATABASE_URL },
});

// Apply as NestJS middleware
app.use("/api/theauth", theAuthMiddleware({ theauth, authenticate }));
```

## Management routes and client IP

With the default session guard, a signed-in user only acts on their own agents, delegations and audit rows. A custom `authenticate` resolver is a trust decision and sees everything.

The adapter does not read forwarded headers for the client IP. Behind a proxy, set `trustedProxy` with `trustedProxyCount` or `trustedHeader`, or `ipAllowlist` constraints cannot match.

```ts
TheAuthModule.forRoot({ theauth, authenticate, trustedProxy: { trustedProxyCount: 1 } })
```

On Cloudflare use `trustedHeader: "cf-connecting-ip"`. Only trust a header your edge overwrites. Without `trustedProxy` the adapter uses `req.ip`, which is the socket peer unless your server framework is configured to trust the proxy.

## Docs

[docs.theauth.dev/adapters/nestjs](https://docs.theauth.dev/adapters/nestjs)

## License

MIT
