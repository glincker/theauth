# __APP_NAME__

A Cloudflare Worker scaffolded with [theAuth](https://theauth.dev). Hono routes, D1 for storage, deployed with wrangler.

## Getting started

```bash
cp .dev.vars.example .dev.vars
# Edit .dev.vars: set SESSION_SECRET to a random string of 32+ characters

pnpm install
pnpm dev
```

Tables are created on the first request. `GET /health` answers without touching the database.

## Deploy

```bash
npx wrangler d1 create __APP_NAME__-db
# Paste the returned database_id into wrangler.toml
npx wrangler secret put SESSION_SECRET
pnpm deploy
```

## Before you ship

The generated worker mounts the management routes with `allowUnauthenticated: true` so you can try it out. Pass an `authenticate` function to `theAuthHono` before exposing it. See the Hono adapter docs.
