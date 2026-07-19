---
title: Adapters Catalog
description: All available framework and database adapters for TheAuth, with mount patterns and install commands.
---

# Adapters Catalog

## Framework adapters

The `@glinr/theauth` package has zero framework dependencies. It operates on the Web platform `Request`/`Response` API. Framework adapters wrap the core and expose idiomatic handlers.

| Package | Framework | Mount pattern | Guide |
|---|---|---|---|
| `@glinr/theauth-nextjs` | Next.js App Router | catch-all route `app/api/kavach/[...kavach]/route.ts` | [Next.js](../guides/frameworks/nextjs.md) |
| `@glinr/theauth-hono` | Hono | `app.route('/api/kavach', kavachHono(kavach))` | [Hono](../guides/frameworks/hono.md) |
| `@glinr/theauth-express` | Express | `app.use('/api/kavach', kavachExpress(kavach))` | [Express](../guides/frameworks/express.md) |
| `@glinr/theauth-fastify` | Fastify | `app.register(authFastify(kavach), { prefix: '/api/kavach' })` | [Fastify](../guides/frameworks/fastify.md) |
| `@glinr/theauth-nestjs` | NestJS | `TheAuthModule.forRoot({ kavach })` in `AppModule` | [NestJS](../guides/frameworks/nestjs.md) |
| `@glinr/theauth-nuxt` | Nuxt (H3) | catch-all file `server/api/kavach/[...].ts` | [Nuxt](../guides/frameworks/nuxt.md) |
| `@glinr/theauth-sveltekit` | SvelteKit | catch-all route `src/routes/api/kavach/[...path]/+server.ts` | [SvelteKit](../guides/frameworks/sveltekit.md) |
| `@glinr/theauth-astro` | Astro | catch-all page `src/pages/api/kavach/[...path].ts` | [Astro](../guides/frameworks/astro.md) |

## Database adapters

| Package / provider | Notes |
|---|---|
| SQLite (built-in) | Ships with `better-sqlite3`. WAL mode and foreign keys enabled automatically. |
| Postgres (built-in) | Requires `pg` peer dependency. |
| MySQL (built-in) | Requires `mysql2` peer dependency. |
| Cloudflare D1 (built-in) | Pass `D1Database` binding from the Worker environment. |
| `@glinr/theauth-prisma` | Prisma-compatible adapter for use with existing Prisma schemas. |

## Client SDKs

| Package | Runtime | Notes |
|---|---|---|
| `@glinr/theauth-react` | Browser | React hooks and `TheAuthProvider` |
| `@glinr/theauth-vue` | Browser | Vue composables and plugin |
| `@glinr/theauth-svelte` | Browser | Svelte stores |
| `@glinr/theauth-expo` | React Native / Expo | AsyncStorage or SecureStore token storage |
| `@glinr/theauth-electron` | Electron | OS keychain storage, IPC bridge, OAuth popup |
| `@glinr/theauth-client` | Node.js / server | Typed HTTP client for server-to-server calls |

## Observability

| Package | Description |
|---|---|
| `@glinr/theauth/telemetry` (built-in) | OpenTelemetry hooks via `TelemetryConfig` in `createTheAuth` |

!!! info "SIEM and OTLP streaming"
    A dedicated `@glinr/audit-otlp` package for streaming audit events to OTLP collectors (Datadog, Splunk, Grafana) is planned. Track the GitHub repository for status.

!!! info "Storagetest contract suite"
    A TypeScript equivalent of the storagetest contract suite for verifying custom database adapters is planned.

## Endpoints registered by all adapters

Every framework adapter registers the same REST endpoints at its mount path (default `/api/kavach`):

| Method | Path | Description |
|---|---|---|
| `POST` | `/agents` | Create an agent |
| `GET` | `/agents` | List agents |
| `GET` | `/agents/:id` | Get an agent |
| `PATCH` | `/agents/:id` | Update an agent |
| `DELETE` | `/agents/:id` | Revoke an agent |
| `POST` | `/agents/:id/rotate` | Rotate token |
| `POST` | `/authorize` | Authorize by agent ID |
| `POST` | `/authorize/token` | Authorize by bearer token |
| `POST` | `/delegations` | Create delegation |
| `GET` | `/delegations/:agentId` | List delegation chains |
| `DELETE` | `/delegations/:id` | Revoke delegation |
| `GET` | `/audit` | Query audit logs |
| `GET` | `/audit/export` | Export audit logs |

Plus, when `mcp` is passed:

| Method | Path | RFC |
|---|---|---|
| `GET` | `/.well-known/oauth-authorization-server` | RFC 8414 |
| `GET` | `/.well-known/oauth-protected-resource` | RFC 9728 |
| `POST` | `/oauth/register` | RFC 7591 |
| `GET` | `/oauth/authorize` | OAuth 2.1 |
| `POST` | `/oauth/token` | OAuth 2.1 |
| `POST` | `/oauth/revoke` | RFC 7009 |
