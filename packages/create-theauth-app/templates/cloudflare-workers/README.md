# __APP_NAME__

A Cloudflare Worker scaffolded with [theAuth](https://theauth.dev). Hono routes, D1 for storage, deployed with wrangler.

## Getting started

```bash
# create-theauth-app already wrote .dev.vars with generated SESSION_SECRET and ADMIN_API_KEY

pnpm install
pnpm dev
```

Tables are created on the first request. `GET /health` answers without touching the database.

## Deploy

```bash
npx wrangler d1 create __APP_NAME__-db
# Paste the returned database_id into wrangler.toml
npx wrangler secret put SESSION_SECRET
npx wrangler secret put ADMIN_API_KEY
pnpm deploy
```

## Before you ship

The management routes (`/api/agents`, `/api/audit` and the rest) require `Authorization: Bearer <ADMIN_API_KEY>`. The worker creates the owner user with `auth.user.create` before the first request, so agents you create for it satisfy the foreign key. Swap the key check for your own session or SSO logic before you expose it. Run `pnpm doctor` to check the setup.
