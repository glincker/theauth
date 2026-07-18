# @glinr/theauth-nuxt

Nuxt adapter for TheAuth.

[![npm](https://img.shields.io/npm/v/@glinr/theauth-nuxt)](https://www.npmjs.com/package/@glinr/theauth-nuxt)

## Install

```bash
pnpm add theauth @glinr/@glinr/theauth-nuxt
```

## Usage

Create `server/api/kavach/[...].ts`:

```typescript
import { createTheAuth } from '@glinr/theauth';
import { kavachNuxt } from '@glinr/theauth-nuxt';

const kavach = createTheAuth({
  database: { provider: 'sqlite', url: 'kavach.db' },
});

export default kavachNuxt(kavach);
```

This handles the full TheAuth REST API under `/api/kavach`: agent CRUD, authorization, delegations, audit logs, and dashboard stats.

### With MCP OAuth 2.1

```typescript
import { createMcpModule } from '@glinr/theauth/mcp';
import { kavachNuxt } from '@glinr/theauth-nuxt';

const mcp = createMcpModule({
  issuer: 'https://your-app.com',
  // ...
});

export default kavachNuxt(kavach, { mcp });
```

When `mcp` is provided, the OAuth 2.1 endpoints are enabled:

- `GET /.well-known/oauth-authorization-server`
- `GET /.well-known/oauth-protected-resource`
- `POST /mcp/register`
- `GET /mcp/authorize`
- `POST /mcp/token`

## API surface

`kavachNuxt(kavach, options?)` returns an H3 `EventHandler` for use as a Nuxt server route.

| Option | Type | Description |
|--------|------|-------------|
| `mcp` | `McpAuthModule` | Enables MCP OAuth 2.1 endpoints |
| `basePath` | `string` | URL prefix before the catch-all segment. Defaults to `/api/kavach` |

For full docs on agent identity, permissions, delegation, and audit, see the main [@glinr/theauth](https://www.npmjs.com/package/@glinr/theauth) package.

## Links

- [Documentation](https://theauth.dev/docs)
- [GitHub](https://github.com/glincker/theauth)

## License

MIT
