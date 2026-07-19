---
title: MCP Authorization
description: Configure TheAuth as an OAuth 2.1 authorization server for the Model Context Protocol. Implements PKCE S256, RFC 9728, RFC 8414, RFC 8707, and RFC 7591.
---

# MCP Authorization

The Model Context Protocol defines how AI clients connect to tool servers. The 2025-03 revision added an auth layer: MCP servers can now require OAuth 2.1 tokens before accepting tool calls.

TheAuth implements the full MCP auth stack:

- OAuth 2.1 with PKCE (S256 code challenge method only)
- Protected Resource Metadata (RFC 9728)
- Authorization Server Metadata (RFC 8414)
- Resource Indicators (RFC 8707)
- Dynamic Client Registration (RFC 7591)

## Setup

```typescript
import { createTheAuth } from '@glinr/theauth';

const kavach = createTheAuth({
  database: { provider: 'sqlite', url: 'kavach.db' },
  baseUrl: 'https://auth.yourapp.com',
  mcp: {
    issuer: 'https://auth.yourapp.com',
    audience: 'https://mcp.yourapp.com',
    accessTokenTtl: 3600,    // seconds
    refreshTokenTtl: 86400,
  },
});
```

Then mount the MCP module via a framework adapter. See [Framework Adapters](../reference/adapters.md) for how to pass `createMcpModule` to your adapter.

## MCP config options

| Option | Type | Description |
|---|---|---|
| `issuer` | `string` | The authorization server URL. Appears in token claims and metadata documents. |
| `audience` | `string` | The protected resource URL. Tokens are bound to this audience and rejected by any other server. |
| `accessTokenTtl` | `number` | Access token lifetime in seconds. Defaults to 3600. |
| `refreshTokenTtl` | `number` | Refresh token lifetime in seconds. Defaults to 86400. Rotation is applied on each use for public clients. |
| `enforceAuth` | `boolean` | Reject all MCP requests without a valid Bearer token. |
| `scopes` | `string[]` | Custom OAuth scopes supported by this server. |
| `loginPage` | `string` | URL of your login page. Users are redirected here when unauthenticated. |
| `consentPage` | `string` | URL of your consent page. Users are redirected here to approve scopes. |
| `preRegisteredClients` | `Array<...>` | OAuth clients registered at startup (first-party apps, CLIs, test fixtures). |

## Endpoints

Once mounted, TheAuth serves these endpoints (relative to your `basePath`, default `/api/kavach`):

| Endpoint | RFC | Purpose |
|---|---|---|
| `GET /.well-known/oauth-authorization-server` | RFC 8414 | Authorization server metadata |
| `GET /.well-known/oauth-protected-resource` | RFC 9728 | Protected resource metadata |
| `POST /oauth/register` | RFC 7591 | Dynamic client registration |
| `GET /oauth/authorize` | OAuth 2.1 | Authorization endpoint |
| `POST /oauth/token` | OAuth 2.1 | Token endpoint |
| `POST /oauth/revoke` | RFC 7009 | Token revocation |

## Standards tracked

TheAuth tracks the two emerging IETF drafts for agent authorization:

- `draft-goswami-agentic-jwt-00` (agentic JWT claims)
- `draft-liu-agent-operation-authorization-01` (three-layer user-workload-token binding)

See [Standards Alignment](standards.md) for details on emitting the matching claims on issued tokens.

!!! info "DPoP (RFC 9449)"
    DPoP support is not yet shipped in the TypeScript library. If you need sender-constrained tokens for your MCP server, track the GitHub issue for status.

## Related pages

- [Standards Alignment](standards.md)
- [Reference: Adapters](../reference/adapters.md)
- [Reference: Configuration](../reference/configuration.md)
