# @glinr/theauth-sveltekit

[npm](https://www.npmjs.com/package/@glinr/theauth-sveltekit) · [Source](https://github.com/glincker/theauth/tree/main/packages/adapters/sveltekit) · [Docs](https://docs.theauth.dev/adapters/sveltekit) · [All packages](https://github.com/glincker/theauth#packages)

SvelteKit adapter for theAuth.

[![npm](https://img.shields.io/npm/v/@glinr/theauth-sveltekit)](https://www.npmjs.com/package/@glinr/theauth-sveltekit)

Part of [theAuth](https://theauth.dev), open-source auth for AI agents and humans. Docs: [docs.theauth.dev](https://docs.theauth.dev).

## Install

```bash
pnpm add @glinr/theauth @glinr/theauth-sveltekit
```

## Usage

Create `src/routes/api/theauth/[...path]/+server.ts`:

```typescript
import { createTheAuth } from '@glinr/theauth';
import { theAuthSvelteKit } from '@glinr/theauth-sveltekit';

const theauth = createTheAuth({
  database: { provider: 'sqlite-native', url: 'theauth.db' },
});

const handlers = theAuthSvelteKit(theauth, { authenticate });

export const GET = handlers.GET;
export const POST = handlers.POST;
export const PATCH = handlers.PATCH;
export const DELETE = handlers.DELETE;
export const OPTIONS = handlers.OPTIONS;
```

This handles the full theAuth REST API under `/api/theauth`: agent CRUD, authorization, delegations, audit logs, and dashboard stats.

### With MCP OAuth 2.1

```typescript
import { createMcpModule } from '@glinr/theauth/mcp';
import { theAuthSvelteKit } from '@glinr/theauth-sveltekit';

const mcp = createMcpModule({
  issuer: 'https://your-app.com',
  // ...
});

const handlers = theAuthSvelteKit(theauth, { mcp, authenticate });
```

When `mcp` is provided, the OAuth 2.1 endpoints are enabled:

- `GET /.well-known/oauth-authorization-server`
- `GET /.well-known/oauth-protected-resource`
- `POST /mcp/register`
- `GET /mcp/authorize`
- `POST /mcp/token`
- `POST /mcp/revoke`
- `GET /mcp/jwks`

## Management routes and client IP

With the default session guard, a signed-in user only acts on their own agents, delegations and audit rows. A custom `authenticate` resolver is a trust decision and sees everything.

The adapter does not read forwarded headers for the client IP. Behind a proxy, set `trustedProxy` with `trustedProxyCount` or `trustedHeader`, or `ipAllowlist` constraints cannot match.

```ts
const handlers = theAuthSvelteKit(theauth, { authenticate, trustedProxy: { trustedProxyCount: 1 } });
```

On Cloudflare use `trustedHeader: "cf-connecting-ip"`. Only trust a header your edge overwrites.


## Options

`theAuthSvelteKit(theauth, options?)` takes the same options as the core handler (`createTheAuthHandler` from `@glinr/theauth/http`), so they are identical on every adapter:

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
import { requireScope } from '@glinr/theauth-sveltekit';

export const GET = requireScope(
  theauth,
  { action: 'read', resource: 'invoices' },
  ({ locals }) => Response.json({ agent: locals.agent.id }),
);
```

`requireScope(theauth, { action, resource }, handler)` reads the agent bearer token and checks it may perform the action. It answers 401 (`invalid_token`, `agent_not_found`, `agent_revoked`, `agent_expired`) or 403 (any other denial) with body `{ "error": { "code", "message" } }`, and otherwise passes the agent (without its token) on via `event.locals.agent`. Pass `clientIp` to feed `ipAllowlist` constraints.

## Links

- [Documentation](https://docs.theauth.dev)
- [GitHub](https://github.com/glincker/theauth)

## License

MIT

<!-- theauth:links -->
## Learn more

- [sveltekit adapter guide](https://docs.theauth.dev/adapters/sveltekit)
- [All adapters](https://docs.theauth.dev/adapters)
- [All packages](https://github.com/glincker/theauth#packages)
- [GitHub Discussions](https://github.com/glincker/theauth/discussions) for questions
- [Report a security issue](https://github.com/glincker/theauth/blob/main/SECURITY.md)
