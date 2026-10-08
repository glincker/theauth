# @glinr/theauth-express

[npm](https://www.npmjs.com/package/@glinr/theauth-express) · [Source](https://github.com/glincker/theauth/tree/main/packages/adapters/express) · [Docs](https://docs.theauth.dev/adapters/express) · [All packages](https://github.com/glincker/theauth#packages)

Express adapter for theAuth.

[![npm](https://img.shields.io/npm/v/@glinr/theauth-express)](https://www.npmjs.com/package/@glinr/theauth-express)

Part of [theAuth](https://theauth.dev), open-source auth for AI agents and humans. Docs: [docs.theauth.dev](https://docs.theauth.dev).

## Install

```bash
pnpm add @glinr/theauth @glinr/theauth-express
```

## Usage

```typescript
import express from 'express';
import { createTheAuth } from '@glinr/theauth';
import { theAuthExpress } from '@glinr/theauth-express';

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const theauth = createTheAuth({
  database: { provider: 'sqlite', url: 'theauth.db' },
});

// Mount all TheAuth routes at /auth
app.use('/auth', theAuthExpress(theauth, { authenticate }));

app.listen(3000);
```

This mounts the full theAuth REST API: agent CRUD, authorization, delegations, audit logs, and dashboard stats.

### With MCP OAuth 2.1

```typescript
import { createMcpModule } from '@glinr/theauth/mcp';
import { theAuthExpress } from '@glinr/theauth-express';

const mcp = createMcpModule({
  issuer: 'https://your-app.com',
  // ...
});

app.use('/auth', theAuthExpress(theauth, { mcp, authenticate }));
```

When `mcp` is provided, the OAuth 2.1 endpoints are enabled:

- `GET /.well-known/oauth-authorization-server`
- `GET /.well-known/oauth-protected-resource`
- `POST /mcp/register`
- `GET /mcp/authorize`
- `POST /mcp/token`

## API surface

`theAuthExpress(theauth, options?)` returns an Express `Router`. Pass it to `app.use()` with your chosen prefix.

| Option | Type | Description |
|--------|------|-------------|
| `mcp` | `McpAuthModule` | Enables MCP OAuth 2.1 endpoints |

For full docs on agent identity, permissions, delegation, and audit, see the main [@glinr/theauth](https://www.npmjs.com/package/@glinr/theauth) package.

## Links

- [Documentation](https://docs.theauth.dev)
- [GitHub](https://github.com/glincker/theauth)

## License

MIT
