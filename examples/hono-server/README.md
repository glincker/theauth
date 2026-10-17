# Hono server example

Full auth server using TheAuth with the Hono adapter. Includes sign-up, sign-in, session management, and agent CRUD.

## Run

```bash
pnpm install
pnpm dev
# Server starts on http://localhost:3000
```

## Endpoints

- `POST /api/theauth/sign-up` - Create account
- `POST /api/theauth/sign-in` - Sign in
- `GET /api/theauth/session` - Get current session
- `POST /api/theauth/sign-out` - Sign out

## Deploy

This example is a Node server that uses `better-sqlite3`, so it cannot run on Cloudflare Workers and has no deploy button. To deploy theAuth with Hono on Cloudflare, use [examples/cloudflare-workers](../cloudflare-workers).
