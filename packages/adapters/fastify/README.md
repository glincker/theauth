# @theauth/fastify

Fastify adapter for TheAuth.

[![npm](https://img.shields.io/npm/v/@theauth/fastify)](https://www.npmjs.com/package/@theauth/fastify)

## Install

```bash
pnpm add theauth @theauth/fastify
```

## Usage

```typescript
import Fastify from 'fastify';
import { createKavach } from 'theauth';
import { kavachFastify } from '@theauth/fastify';

const app = Fastify();

const kavach = createKavach({
  database: { provider: 'sqlite', url: 'kavach.db' },
});

// Register all TheAuth routes under /api/kavach
await app.register(kavachFastify(kavach), { prefix: '/api/kavach' });

await app.listen({ port: 3000 });
```

This registers the full TheAuth REST API: agent CRUD, authorization, delegations, audit logs, and dashboard stats.

### With MCP OAuth 2.1

```typescript
import { createMcpModule } from 'theauth/mcp';
import { kavachFastify } from '@theauth/fastify';

const mcp = createMcpModule({
  issuer: 'https://your-app.com',
  // ...
});

await app.register(kavachFastify(kavach, { mcp }), { prefix: '/api/kavach' });
```

When `mcp` is provided, the OAuth 2.1 endpoints are enabled:

- `GET /.well-known/oauth-authorization-server`
- `GET /.well-known/oauth-protected-resource`
- `POST /mcp/register`
- `GET /mcp/authorize`
- `POST /mcp/token`

## API surface

`kavachFastify(kavach, options?)` returns an async Fastify plugin. Pass it to `app.register()` and use Fastify's built-in `prefix` option to choose your mount path.

| Option | Type | Description |
|--------|------|-------------|
| `mcp` | `McpAuthModule` | Enables MCP OAuth 2.1 endpoints |

For full docs on agent identity, permissions, delegation, and audit, see the main [theauth](https://www.npmjs.com/package/theauth) package.

## Links

- [Documentation](https://theauth.dev/docs)
- [GitHub](https://github.com/glincker/theauth)

## License

MIT
