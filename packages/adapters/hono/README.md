# @glinr/theauth-hono

[npm](https://www.npmjs.com/package/@glinr/theauth-hono) · [Source](https://github.com/glincker/theauth/tree/main/packages/adapters/hono) · [Docs](https://docs.theauth.dev/adapters/hono) · [All packages](https://github.com/glincker/theauth#packages)

Hono adapter for theAuth.

[![npm](https://img.shields.io/npm/v/@glinr/theauth-hono)](https://www.npmjs.com/package/@glinr/theauth-hono)

Part of [theAuth](https://theauth.dev), open-source auth for AI agents and humans. Docs: [docs.theauth.dev](https://docs.theauth.dev).

## Install

```bash
pnpm add @glinr/theauth @glinr/theauth-hono
```

## Usage

```typescript
import { serve } from '@hono/node-server';
import { Hono } from 'hono';
import { createTheAuth } from '@glinr/theauth';
import { theAuthHono } from '@glinr/theauth-hono';

const theauth = createTheAuth({
  database: { provider: 'sqlite-native', url: 'theauth.db' },
});

const app = new Hono();

// Mount all TheAuth routes at /api/theauth
app.route('/api/theauth', theAuthHono(theauth, { authenticate }));

serve({ fetch: app.fetch, port: 3000 });
```

This mounts the full theAuth REST API: agent CRUD, authorization, delegations, audit logs, and dashboard stats.

### With MCP OAuth 2.1

```typescript
import { createMcpModule } from '@glinr/theauth/mcp';
import { theAuthHono } from '@glinr/theauth-hono';

const mcp = createMcpModule({
  issuer: 'https://your-app.com',
  // ...
});

app.route('/api/theauth', theAuthHono(theauth, { mcp, authenticate }));
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
app.route("/api/theauth", theAuthHono(theauth, { authenticate, trustedProxy: { trustedProxyCount: 1 } }));
```

On Cloudflare use `trustedHeader: "cf-connecting-ip"`. Only trust a header your edge overwrites.

## Options and routes

The adapter is a thin wrapper around `createTheAuthHandler` from `@glinr/theauth/http`, so it serves the same routes with the same status codes as every other adapter. See the [route reference](https://docs.theauth.dev/adapters/routes).

| Option | Description |
|--------|-------------|
| `mcp` | `McpAuthModule`. Enables the MCP OAuth 2.1 endpoints (register, authorize, token, revoke, jwks, and the two well-known documents) |
| `basePath` | URL prefix the handler is mounted under. Defaults to where you mount the app. |
| `routes` | Turn route groups off: `management`, `mcp`, `plugins`, `explain` |
| `maxBodyBytes` | Largest accepted body. Default 1 MiB, larger gets 413 |
| `authenticate`, `allowUnauthenticated`, `trustedProxy`, `rateLimit`, `trustedOrigins`, `csrf` | Shared security options |

### Upgrading to 2.0

Options are the core handler options, and the deprecated aliases are gone. See the changeset notes in the changelog.

## Links

- [Documentation](https://docs.theauth.dev)
- [GitHub](https://github.com/glincker/theauth)

## License

MIT

<!-- theauth:links -->
## Protect a route for agents

```ts
import { Hono } from "hono";
import { requireScope, type AgentEnv } from "@glinr/theauth-hono";

const app = new Hono<AgentEnv>();
app.get("/invoices", requireScope(theauth, { action: "read", resource: "invoices" }), (c) =>
  c.json({ agentId: c.get("agent").id }),
);
```

Missing or invalid bearer token returns 401, a denied scope returns 403. The body is `{ "error": { "code", "message" } }` where `code` is the decision code (for example `no_permission`). See the [requireScope guide](https://docs.theauth.dev/require-scope).

## Learn more

- [hono adapter guide](https://docs.theauth.dev/adapters/hono)
- [All adapters](https://docs.theauth.dev/adapters)
- [All packages](https://github.com/glincker/theauth#packages)
- [GitHub Discussions](https://github.com/glincker/theauth/discussions) for questions
- [Report a security issue](https://github.com/glincker/theauth/blob/main/SECURITY.md)
