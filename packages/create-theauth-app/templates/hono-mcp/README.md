# __APP_NAME__

A Hono server scaffolded with [theAuth](https://theauth.dev). Runs as an MCP OAuth 2.1 authorization server and a resource server in one process.

## What's included

- **Hono 4** on Node.js
- **theAuth** for agent identity, session management, and the MCP OAuth 2.1 stack
- **__DB_DRIVER__** storing the auth schema (users, agents, audit) in a database file or server, so data survives restarts
- `GET /tools/list` and `POST /tools/call/:name` protected with `withMcpAuth`
- `.well-known` discovery documents for MCP clients, served under `/api` (check with `pnpm run doctor:live`)

## Getting started

```bash
# create-theauth-app already wrote .env with generated THEAUTH_SECRET, ADMIN_API_KEY
# and MCP_SIGNING_SECRET. .env is gitignored.

pnpm install
pnpm run dev
```

theAuth creates the auth tables on first boot. `pnpm run doctor` checks the setup, and `pnpm run doctor:live` also calls the running server.

On boot the server creates the owner user with `theauth.user.create` and prints its id. Agents reference their owner by foreign key, so use that id as `ownerId` below.

**MCP stores are in memory.** Registered clients, authorization codes and tokens are held in maps in `src/server.ts` and reset on restart. Database backed MCP stores are not available yet, so this template does not use them.

The server listens on `http://localhost:3001`. Visit the root URL to see the MCP discovery links and the list of tools.

## Smoke test without an MCP client

```bash
# 1. Create an agent with scoped MCP permissions
curl -X POST http://localhost:3001/api/agents \
  -H "Authorization: Bearer $ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "ownerId": "OWNER_ID_FROM_THE_BOOT_LOG",
    "name": "demo-agent",
    "type": "autonomous",
    "permissions": [
      { "resource": "mcp:*", "actions": ["read", "execute"] }
    ]
  }'

# Copy the ta_... token from the response, then call the protected route:
curl http://localhost:3001/tools/list \
  -H "Authorization: Bearer ta_YOUR_TOKEN"
```

## Environment variables

| Variable          | Required | Notes                                                                      |
|-------------------|----------|----------------------------------------------------------------------------|
| `THEAUTH_SECRET` | Yes      | Long random string. Signs sessions and access tokens.                      |
| `ADMIN_API_KEY`   | Yes      | Bearer key for `/api/agents`, `/api/audit` and the other management routes. Unset means those routes reject every request. |
| `DATABASE_URL`    | Yes      | SQLite: `./theauth.db`. Postgres: `postgres://user:pass@host:5432/db`. |
| `MCP_SIGNING_SECRET` | Yes   | At least 32 characters. Signs MCP JWT access tokens. |
| `OWNER_EMAIL`     | No       | Email of the owner user created on boot. Defaults to `owner@example.com`. |
| `BASE_URL`        | No       | Public URL this server is reachable at. Defaults to `http://localhost:3001`. Set it before deploying so the `.well-known` documents and access-token audience match what clients use. |
| `PORT`            | No       | Port to bind. Defaults to `3001`.                                           |

## Project structure

```
src/
  server.ts            Hono app, MCP mount, protected tool routes
  tools.ts             Example MCP tool list
  lib/
    theauth.ts          Lazy createTheAuth singleton
    admin-auth.ts       Bearer-key check for the management routes
```

## Deploying

Any Node runtime works. Set `BASE_URL` to your public URL before boot so MCP clients find the right endpoints, and set a real `THEAUTH_SECRET` out of band.

To use Postgres, scaffold with the Postgres driver and point `DATABASE_URL` at your connection string. theAuth creates the tables on boot.

## Next

- Replace the example tools in `src/tools.ts` with real implementations.
- Add per-tool permission constraints to the agents you create (rate limits, approval gates, IP allowlists) so agents cannot over-reach.
- Drop a frontend alongside this API, or consume it from any MCP-aware client.
