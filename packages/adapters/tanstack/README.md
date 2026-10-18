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
  database: { provider: "sqlite-native", url: "theauth.db" },
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

## Options

`theAuthTanStack(theauth, options?)` takes the same options as the core handler (`createTheAuthHandler` from `@glinr/theauth/http`), so they are identical on every adapter:

| Option | Type | Description |
|--------|------|-------------|
| `mcp` | `McpAuthModule` | Enables the MCP OAuth 2.1 endpoints |
| `basePath` | `string` | URL prefix before the catch-all segment. Defaults to `/api/theauth` |
| `routes` | `{ management?, mcp?, plugins?, explain? }` | Turn route groups off. `mcp` also takes `{ register, authorize, token, revoke, jwks }` booleans |
| `maxBodyBytes` | `number` | Largest request body, default 1 MiB (413 above it) |
| `authenticate`, `allowUnauthenticated`, `trustedProxy`, `rateLimit`, `trustedOrigins`, `csrf` | | Shared security options |

Every route and status code is listed on the [route reference](https://docs.theauth.dev/adapters/routes).

## Protect a route with `requireScope`

```typescript
import { requireScope } from '@glinr/theauth-tanstack';

GET: requireScope(
  theauth,
  { action: 'read', resource: 'invoices' },
  (event, agent) => Response.json({ agent: agent.id }),
),
```

`requireScope(theauth, { action, resource }, handler)` reads the agent bearer token and checks it may perform the action. It answers 401 (`invalid_token`, `agent_not_found`, `agent_revoked`, `agent_expired`) or 403 (any other denial) with body `{ "error": { "code", "message" } }`, and otherwise passes the agent (without its token) on via the second argument (and `context.agent` when the route context has one). Pass `clientIp` to feed `ipAllowlist` constraints.

## Docs

[docs.theauth.dev/adapters/tanstack](https://docs.theauth.dev/adapters/tanstack)

## License

MIT

<!-- theauth:links -->
## Learn more

- [tanstack adapter guide](https://docs.theauth.dev/adapters/tanstack)
- [All adapters](https://docs.theauth.dev/adapters)
- [All packages](https://github.com/glincker/theauth#packages)
- [GitHub Discussions](https://github.com/glincker/theauth/discussions) for questions
- [Report a security issue](https://github.com/glincker/theauth/blob/main/SECURITY.md)
