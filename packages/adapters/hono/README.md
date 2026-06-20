# @theauth/hono

Hono adapter for TheAuth.

[![npm](https://img.shields.io/npm/v/@theauth/hono)](https://www.npmjs.com/package/@theauth/hono)

## Install

```bash
pnpm add theauth @theauth/hono
```

## Usage

```typescript
import { serve } from '@hono/node-server';
import { Hono } from 'hono';
import { createKavach } from 'theauth';
import { kavachHono } from '@theauth/hono';

const kavach = createKavach({
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
import { createMcpModule } from 'theauth/mcp';
import { kavachHono } from '@theauth/hono';

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

For full docs on agent identity, permissions, delegation, and audit, see the main [theauth](https://www.npmjs.com/package/theauth) package.

## Links

- [Documentation](https://theauth.dev/docs)
- [GitHub](https://github.com/glincker/theauth)

## License

MIT
