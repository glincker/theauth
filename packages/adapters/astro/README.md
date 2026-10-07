# @glinr/theauth-astro

Astro adapter for TheAuth.

[![npm](https://img.shields.io/npm/v/@glinr/theauth-astro)](https://www.npmjs.com/package/@glinr/theauth-astro)

Part of [theAuth](https://theauth.dev), open-source auth for AI agents and humans. Docs: [docs.theauth.dev](https://docs.theauth.dev).

## Install

```bash
pnpm add @glinr/theauth @glinr/theauth-astro
```

## Usage

Create `src/pages/api/theauth/[...path].ts`:

```typescript
import { createTheAuth } from '@glinr/theauth';
import { theAuthAstro } from '@glinr/theauth-astro';

const theauth = createTheAuth({
  database: { provider: 'sqlite', url: 'theauth.db' },
});

const handlers = theAuthAstro(theauth);

export const GET = handlers.GET;
export const POST = handlers.POST;
export const PATCH = handlers.PATCH;
export const DELETE = handlers.DELETE;
export const OPTIONS = handlers.OPTIONS;
```

Or use the catch-all handler to avoid listing each method:

```typescript
export const ALL = handlers.ALL;
```

This handles the full TheAuth REST API under `/api/theauth`: agent CRUD, authorization, delegations, audit logs, and dashboard stats.

### With MCP OAuth 2.1

```typescript
import { createMcpModule } from '@glinr/theauth/mcp';
import { theAuthAstro } from '@glinr/theauth-astro';

const mcp = createMcpModule({
  issuer: 'https://your-app.com',
  // ...
});

const handlers = theAuthAstro(theauth, { mcp });
```

When `mcp` is provided, the OAuth 2.1 endpoints are enabled:

- `GET /.well-known/oauth-authorization-server`
- `GET /.well-known/oauth-protected-resource`
- `POST /mcp/register`
- `GET /mcp/authorize`
- `POST /mcp/token`

## API surface

`theAuthAstro(theauth, options?)` returns an object with `GET`, `POST`, `PATCH`, `DELETE`, `OPTIONS`, and `ALL` handlers for Astro API routes.

| Option | Type | Description |
|--------|------|-------------|
| `mcp` | `McpAuthModule` | Enables MCP OAuth 2.1 endpoints |
| `basePath` | `string` | URL prefix before the catch-all segment. Defaults to `/api/theauth` |

For full docs on agent identity, permissions, delegation, and audit, see the main [@glinr/theauth](https://www.npmjs.com/package/@glinr/theauth) package.

## Links

- [Documentation](https://docs.theauth.dev/docs)
- [GitHub](https://github.com/glincker/theauth)

## License

MIT
