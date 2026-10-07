# @glinr/theauth-sveltekit

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
  database: { provider: 'sqlite', url: 'theauth.db' },
});

const handlers = theAuthSvelteKit(theauth);

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

const handlers = theAuthSvelteKit(theauth, { mcp });
```

When `mcp` is provided, the OAuth 2.1 endpoints are enabled:

- `GET /.well-known/oauth-authorization-server`
- `GET /.well-known/oauth-protected-resource`
- `POST /mcp/register`
- `GET /mcp/authorize`
- `POST /mcp/token`

## API surface

`theAuthSvelteKit(theauth, options?)` returns an object with `GET`, `POST`, `PATCH`, `DELETE`, and `OPTIONS` handlers for SvelteKit's `+server.ts` files.

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
