# MCP server example

KavachOS as an MCP OAuth 2.1 authorization server. Demonstrates PKCE, resource indicators, and protected resource metadata.

## Run

```bash
pnpm install
pnpm dev
```

## Endpoints

- `GET /.well-known/oauth-authorization-server` - Server metadata
- `POST /authorize` - Authorization endpoint
- `POST /token` - Token endpoint
- `POST /register` - Dynamic client registration
