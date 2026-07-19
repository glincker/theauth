# @glinr/theauth-hono

Hono adapter for TheAuth.

[![npm](https://img.shields.io/npm/v/@glinr/theauth-hono)](https://www.npmjs.com/package/@glinr/theauth-hono)

## Install

```bash
pnpm add theauth @glinr/@glinr/theauth-hono
```

## Usage

```typescript
import { serve } from '@hono/node-server';
import { Hono } from 'hono';
import { createTheAuth } from '@glinr/theauth';
import { kavachHono } from '@glinr/theauth-hono';

const kavach = createTheAuth({
  database: { provider: 'sqlite', url: 'kavach.db' },
});

const app = new Hono();

// Mount all TheAuth routes at /api/kavach
app.route('/api/kavach', kavachHono(kavach));

serve({ fetch: app.fetch, port: 3000 });
```

This mounts the full TheAuth REST API: agent CRUD, authorization, delegations, audit logs, and dashboard stats.

### With MCP OAuth 2.1

```typescript
import { createMcpModule } from '@glinr/theauth/mcp';
import { kavachHono } from '@glinr/theauth-hono';

const mcp = createMcpModule({
  issuer: 'https://your-app.com',
  // ...
});

app.route('/api/kavach', kavachHono(kavach, { mcp }));
```

When `mcp` is provided, the OAuth 2.1 endpoints are enabled:

- `GET /.well-known/oauth-authorization-server`
- `GET /.well-known/oauth-protected-resource`
- `POST /mcp/register`
- `GET /mcp/authorize`
- `POST /mcp/token`

## API surface

`kavachHono(kavach, options?)` returns a `Hono` instance with all routes registered. Pass it to `app.route()` with your chosen prefix.

| Option | Type | Description |
|--------|------|-------------|
| `mcp` | `McpAuthModule` | Enables MCP OAuth 2.1 endpoints |

For full docs on agent identity, permissions, delegation, and audit, see the main [@glinr/theauth](https://www.npmjs.com/package/@glinr/theauth) package.

## Links

- [Documentation](https://theauth.dev/docs)
- [GitHub](https://github.com/glincker/theauth)

## License

MIT
