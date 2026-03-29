# Hono server example

Agent auth server using KavachOS with the Hono adapter. Includes agent CRUD, authorization checks, delegations, audit queries, and dashboard endpoints.

## Run

```bash
pnpm install
pnpm dev
# Server starts on http://localhost:3000
```

## Endpoints

- `POST /api/agents` - Create an agent
- `GET /api/agents` - List agents
- `POST /api/authorize` - Check permissions by agent id
- `POST /api/authorize/token` - Check permissions by bearer token
- `GET /api/audit` - Query the audit trail
- `GET /api/dashboard/stats` - Get summary stats
