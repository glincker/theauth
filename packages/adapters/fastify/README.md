# @glinr/theauth-fastify

Fastify adapter for theAuth.

[![npm](https://img.shields.io/npm/v/@glinr/theauth-fastify)](https://www.npmjs.com/package/@glinr/theauth-fastify)

Part of [theAuth](https://theauth.dev), open-source auth for AI agents and humans. Docs: [docs.theauth.dev](https://docs.theauth.dev).

## Install

```bash
pnpm add @glinr/theauth @glinr/theauth-fastify
```

## Usage

```typescript
import Fastify from 'fastify';
import { createTheAuth } from '@glinr/theauth';
import { theAuthFastify } from '@glinr/theauth-fastify';

const app = Fastify();

const theauth = createTheAuth({
  database: { provider: 'sqlite', url: 'theauth.db' },
});

// Register all TheAuth routes under /api/theauth
await app.register(theAuthFastify(theauth), { prefix: '/api/theauth' });

await app.listen({ port: 3000 });
```

This registers the full theAuth REST API: agent CRUD, authorization, delegations, audit logs, and dashboard stats.

### With MCP OAuth 2.1

```typescript
import { createMcpModule } from '@glinr/theauth/mcp';
import { theAuthFastify } from '@glinr/theauth-fastify';

const mcp = createMcpModule({
  issuer: 'https://your-app.com',
  // ...
});

await app.register(theAuthFastify(theauth, { mcp }), { prefix: '/api/theauth' });
```

When `mcp` is provided, the OAuth 2.1 endpoints are enabled:

- `GET /.well-known/oauth-authorization-server`
- `GET /.well-known/oauth-protected-resource`
- `POST /mcp/register`
- `GET /mcp/authorize`
- `POST /mcp/token`

## API surface

`theAuthFastify(theauth, options?)` returns an async Fastify plugin. Pass it to `app.register()` and use Fastify's built-in `prefix` option to choose your mount path.

| Option | Type | Description |
|--------|------|-------------|
| `mcp` | `McpAuthModule` | Enables MCP OAuth 2.1 endpoints |

For full docs on agent identity, permissions, delegation, and audit, see the main [@glinr/theauth](https://www.npmjs.com/package/@glinr/theauth) package.

## Links

- [Documentation](https://docs.theauth.dev)
- [GitHub](https://github.com/glincker/theauth)

## License

MIT
