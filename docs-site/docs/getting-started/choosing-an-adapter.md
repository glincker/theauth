---
title: Choosing an Adapter
description: Pick the right storage and framework adapter for your TheAuth deployment.
---

# Choosing an Adapter

TheAuth has two kinds of adapters: **database adapters** (which database to use) and **framework adapters** (which web framework to mount on).

## Database adapters

| Provider | Best for |
|---|---|
| `sqlite` | Local dev, single-server deploys, serverless edge with Turso |
| `postgres` | Production, high-concurrency, multi-tenant |
| `mysql` | Existing MySQL infrastructure |
| `d1` | Cloudflare Workers, edge-native deployments |

For configuration details, see [Database Setup](../guides/database.md).

## Framework adapters

The `@glinr/theauth` package has zero framework dependencies. It operates on the Web platform `Request`/`Response` API. Framework adapters wrap the core and expose idiomatic handlers.

| Package | Framework | Mount pattern |
|---|---|---|
| `@glinr/theauth-hono` | Hono | `app.route('/api/kavach', kavachHono(kavach))` |
| `@glinr/theauth-express` | Express | `app.use('/api/kavach', kavachExpress(kavach))` |
| `@glinr/theauth-nextjs` | Next.js App Router | catch-all route `app/api/kavach/[...kavach]/route.ts` |
| `@glinr/theauth-fastify` | Fastify | `app.register(authFastify(kavach), { prefix: '/api/kavach' })` |
| `@glinr/theauth-nuxt` | Nuxt (H3) | catch-all file `server/api/kavach/[...].ts` |
| `@glinr/theauth-sveltekit` | SvelteKit | catch-all route `src/routes/api/kavach/[...path]/+server.ts` |
| `@glinr/theauth-astro` | Astro | catch-all page `src/pages/api/kavach/[...path].ts` |

## Edge compatibility

Because core uses only Web platform APIs, TheAuth runs on edge runtimes without modification. The Hono and SvelteKit adapters are fully edge-compatible. The Next.js adapter works on edge when you add `export const runtime = 'edge'` to your route file.

## Prisma users

A Prisma-compatible adapter is available:

```bash
pnpm add @glinr/theauth-prisma
```

See the [Adapters Catalog](../reference/adapters.md) for configuration details.

## Next steps

- [Installation](installation.md)
- [Quick Start](quick-start.md)
- [Database Setup](../guides/database.md)
