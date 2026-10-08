# @glinr/theauth-nuxt

[npm](https://www.npmjs.com/package/@glinr/theauth-nuxt) · [Source](https://github.com/glincker/theauth/tree/main/packages/adapters/nuxt) · [Docs](https://docs.theauth.dev/adapters/nuxt) · [All packages](https://github.com/glincker/theauth#packages)

Nuxt adapter for theAuth.

[![npm](https://img.shields.io/npm/v/@glinr/theauth-nuxt)](https://www.npmjs.com/package/@glinr/theauth-nuxt)

Part of [theAuth](https://theauth.dev), open-source auth for AI agents and humans. Docs: [docs.theauth.dev](https://docs.theauth.dev).

## Install

```bash
pnpm add @glinr/theauth @glinr/theauth-nuxt
```

## Usage

Create `server/api/theauth/[...].ts`:

```typescript
import { createTheAuth } from '@glinr/theauth';
import { theAuthNuxt } from '@glinr/theauth-nuxt';

const theauth = createTheAuth({
  database: { provider: 'sqlite', url: 'theauth.db' },
});

export default theAuthNuxt(theauth, { authenticate });
```

This handles the full theAuth REST API under `/api/theauth`: agent CRUD, authorization, delegations, audit logs, and dashboard stats.

### With MCP OAuth 2.1

```typescript
import { createMcpModule } from '@glinr/theauth/mcp';
import { theAuthNuxt } from '@glinr/theauth-nuxt';

const mcp = createMcpModule({
  issuer: 'https://your-app.com',
  // ...
});

export default theAuthNuxt(theauth, { mcp, authenticate });
```

When `mcp` is provided, the OAuth 2.1 endpoints are enabled:

- `GET /.well-known/oauth-authorization-server`
- `GET /.well-known/oauth-protected-resource`
- `POST /mcp/register`
- `GET /mcp/authorize`
- `POST /mcp/token`

## API surface

`theAuthNuxt(theauth, options?)` returns an H3 `EventHandler` for use as a Nuxt server route.

| Option | Type | Description |
|--------|------|-------------|
| `mcp` | `McpAuthModule` | Enables MCP OAuth 2.1 endpoints |
| `basePath` | `string` | URL prefix before the catch-all segment. Defaults to `/api/theauth` |

For full docs on agent identity, permissions, delegation, and audit, see the main [@glinr/theauth](https://www.npmjs.com/package/@glinr/theauth) package.

## Links

- [Documentation](https://docs.theauth.dev)
- [GitHub](https://github.com/glincker/theauth)

## License

MIT
