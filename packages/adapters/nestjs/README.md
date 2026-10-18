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

On Cloudflare use `trustedHeader: "cf-connecting-ip"`. Only trust a header your edge overwrites.

## Options and routes

The adapter is a thin wrapper around `createTheAuthHandler` from `@glinr/theauth/http`, so it serves the same routes with the same status codes as every other adapter. See the [route reference](https://docs.theauth.dev/adapters/routes).

| Option | Description |
|--------|-------------|
| `mcp` | `McpAuthModule`. Enables the MCP OAuth 2.1 endpoints (register, authorize, token, revoke, jwks, and the two well-known documents) |
| `basePath` | URL prefix the handler is mounted under. Defaults to `/api/theauth` in `TheAuthModule`, and to the mount point for `theAuthMiddleware`. |
| `routes` | Turn route groups off: `management`, `mcp`, `plugins`, `explain` |
| `maxBodyBytes` | Largest accepted body. Default 1 MiB, larger gets 413 |
| `authenticate`, `allowUnauthenticated`, `trustedProxy`, `rateLimit`, `trustedOrigins`, `csrf` | Shared security options |

## Protect a route for agents

```ts
import { Controller, Get, Req, UseGuards } from "@nestjs/common";
import { getAgent, requireScope } from "@glinr/theauth-nestjs";

@Controller("invoices")
export class InvoicesController {
  @Get()
  @UseGuards(requireScope(theauth, { action: "read", resource: "invoices" }))
  list(@Req() req: { agent?: { id: string } }) {
    return { agentId: getAgent(req)?.id };
  }
}
```

Missing or invalid bearer token returns 401, a denied scope returns 403. The body is `{ "error": { "code", "message" } }` where `code` is the decision code (for example `no_permission`). See the [requireScope guide](https://docs.theauth.dev/require-scope).

### Upgrading to 2.0

Options are the core handler options, and the deprecated aliases are gone. See the changeset notes in the changelog.

## Docs

[docs.theauth.dev/adapters/nestjs](https://docs.theauth.dev/adapters/nestjs)

## License

MIT

<!-- theauth:links -->
## Learn more

- [nestjs adapter guide](https://docs.theauth.dev/adapters/nestjs)
- [All adapters](https://docs.theauth.dev/adapters)
- [All packages](https://github.com/glincker/theauth#packages)
- [GitHub Discussions](https://github.com/glincker/theauth/discussions) for questions
- [Report a security issue](https://github.com/glincker/theauth/blob/main/SECURITY.md)
