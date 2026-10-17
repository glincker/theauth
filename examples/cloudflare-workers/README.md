# Cloudflare Workers example

TheAuth running on Cloudflare Workers with D1 as the database. Zero cold start, global edge deployment.

## Run

```bash
pnpm install
pnpm dev
# Uses wrangler for local development
```

## Deploy

This folder depends on workspace packages (`workspace:*`), so it only installs inside the monorepo and a one-click deploy button would fail. To get a deployable copy, scaffold a standalone project with `npm create theauth-app@latest` and pick the `cloudflare-workers` template, then set the secret with `wrangler secret put SESSION_SECRET` (copy `.dev.vars.example` to `.dev.vars` for local runs).
