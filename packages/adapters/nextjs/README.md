# @glinr/theauth-nextjs

Next.js adapter for TheAuth.

[![npm](https://img.shields.io/npm/v/@glinr/theauth-nextjs)](https://www.npmjs.com/package/@glinr/theauth-nextjs)

## Install

```bash
pnpm add theauth @glinr/@glinr/theauth-nextjs
```

## Usage

Create `app/api/kavach/[...kavach]/route.ts`:

```typescript
import { createKavach } from '@glinr/theauth';
import { kavachNextjs } from '@glinr/theauth-nextjs';

const kavach = createKavach({
  database: { provider: 'sqlite', url: 'kavach.db' },
});

const handlers = kavachNextjs(kavach);

export const GET = handlers.GET;
export const POST = handlers.POST;
export const PATCH = handlers.PATCH;
export const DELETE = handlers.DELETE;
export const OPTIONS = handlers.OPTIONS;
```

This handles the full TheAuth REST API under `/api/kavach`: agent CRUD, authorization, delegations, audit logs, and dashboard stats.

### With MCP OAuth 2.1

```typescript
import { createMcpModule } from '@glinr/theauth/mcp';
import { kavachNextjs } from '@glinr/theauth-nextjs';

const mcp = createMcpModule({
  issuer: 'https://your-app.com',
  // ...
});

const handlers = kavachNextjs(kavach, { mcp });
```

When `mcp` is provided, the OAuth 2.1 endpoints are enabled:

- `GET /.well-known/oauth-authorization-server`
- `GET /.well-known/oauth-protected-resource`
- `POST /mcp/register`
- `GET /mcp/authorize`
- `POST /mcp/token`

## API surface

`kavachNextjs(kavach, options?)` returns an object with `GET`, `POST`, `PATCH`, `DELETE`, and `OPTIONS` handlers for the Next.js App Router.

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
