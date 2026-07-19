# @glinr/theauth-express

Express adapter for TheAuth.

[![npm](https://img.shields.io/npm/v/@glinr/theauth-express)](https://www.npmjs.com/package/@glinr/theauth-express)

## Install

```bash
pnpm add theauth @glinr/@glinr/theauth-express
```

## Usage

```typescript
import express from 'express';
import { createTheAuth } from '@glinr/theauth';
import { kavachExpress } from '@glinr/theauth-express';

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const kavach = createTheAuth({
  database: { provider: 'sqlite', url: 'kavach.db' },
});

// Mount all TheAuth routes at /auth
app.use('/auth', kavachExpress(kavach));

app.listen(3000);
```

This mounts the full TheAuth REST API: agent CRUD, authorization, delegations, audit logs, and dashboard stats.

### With MCP OAuth 2.1

```typescript
import { createMcpModule } from '@glinr/theauth/mcp';
import { kavachExpress } from '@glinr/theauth-express';

const mcp = createMcpModule({
  issuer: 'https://your-app.com',
  // ...
});

app.use('/auth', kavachExpress(kavach, { mcp }));
```

When `mcp` is provided, the OAuth 2.1 endpoints are enabled:

- `GET /.well-known/oauth-authorization-server`
- `GET /.well-known/oauth-protected-resource`
- `POST /mcp/register`
- `GET /mcp/authorize`
- `POST /mcp/token`

## API surface

`kavachExpress(kavach, options?)` returns an Express `Router`. Pass it to `app.use()` with your chosen prefix.

| Option | Type | Description |
|--------|------|-------------|
| `mcp` | `McpAuthModule` | Enables MCP OAuth 2.1 endpoints |

For full docs on agent identity, permissions, delegation, and audit, see the main [@glinr/theauth](https://www.npmjs.com/package/@glinr/theauth) package.

## Links

- [Documentation](https://theauth.dev/docs)
- [GitHub](https://github.com/glincker/theauth)

## License

MIT
