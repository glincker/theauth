# __APP_NAME__

A Hono server scaffolded with [TheAuth](https://theauth.dev). Runs as an MCP OAuth 2.1 authorization server and a resource server in one process.

## What's included

- **Hono 4** on Node.js
- **TheAuth** for agent identity, session management, and the MCP OAuth 2.1 stack
- **Drizzle ORM** with __DB_DRIVER__ backing the auth schema
- `GET /tools/list` and `POST /tools/call/:name` protected with `withMcpAuth`
- `.well-known` discovery documents for MCP clients, served at the root

## Getting started

```bash
cp .env.example .env
# Edit .env: set THEAUTH_SECRET to a 32+ byte random hex string

pnpm install
pnpm run dev
```

TheAuth creates the auth tables on first boot, no separate migration step for SQLite or Postgres.

The server listens on `http://localhost:3001`. Visit the root URL to see the MCP discovery links and the list of tools.

## Smoke test without an MCP client

```bash
# 1. Create an agent with scoped MCP permissions
curl -X POST http://localhost:3001/api/agents \
  -H "Content-Type: application/json" \
  -d '{
    "ownerId": "user-1",
    "name": "demo-agent",
    "type": "autonomous",
    "permissions": [
      { "resource": "mcp:*", "actions": ["read", "execute"] }
    ]
  }'

# Copy the kv_... token from the response, then call the protected route:
curl http://localhost:3001/tools/list \
  -H "Authorization: Bearer kv_YOUR_TOKEN"
```

## Environment variables

| Variable          | Required | Notes                                                                      |
|-------------------|----------|----------------------------------------------------------------------------|
| `THEAUTH_SECRET` | Yes      | Long random string. Signs sessions and access tokens.                      |
| `DATABASE_URL`    | Yes      | SQLite: `file:./kavach.db`. Postgres: `postgres://user:pass@host:5432/db`. |
| `BASE_URL`        | No       | Public URL this server is reachable at. Defaults to `http://localhost:3001`. Set it before deploying so the `.well-known` documents and access-token audience match what clients use. |
| `PORT`            | No       | Port to bind. Defaults to `3001`.                                           |

## Project structure

```
src/
  server.ts            Hono app, MCP mount, protected tool routes
  tools.ts             Example MCP tool list
  lib/
    kavach.ts          Lazy createKavach singleton
```

## Deploying

Any Node runtime works. Set `BASE_URL` to your public URL before boot so MCP clients find the right endpoints, and set a real `THEAUTH_SECRET` out of band.

If you switch to Postgres, set `DB_PROVIDER=postgres` and point `DATABASE_URL` at your connection string. TheAuth creates the tables on boot.

## Next

- Replace the example tools in `src/tools.ts` with real implementations.
- Add per-tool permission constraints to the agents you create (rate limits, approval gates, IP allowlists) so agents cannot over-reach.
- Drop a frontend alongside this API, or consume it from any MCP-aware client.
