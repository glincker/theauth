<p align="center">
  <img src="https://theauth.dev/logo.svg" height="64" alt="theAuth" />
</p>

<h2 align="center"><em>Open-source auth for AI agents and humans.<br>Agent identity, MCP OAuth 2.1, passkeys, SSO.</em></h2>

<p align="center">
  by <a href="https://glincker.com"><strong>GLINCKER</strong></a>, a <a href="https://glinr.com">GLINR STUDIOS</a> company &middot; founded by <a href="https://thegdsks.com">thegdsks</a>
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/@glinr/theauth"><img src="https://img.shields.io/npm/v/@glinr/theauth?style=flat&colorA=000000&colorB=000000&label=npm" alt="npm version" /></a>
  <a href="https://www.npmjs.com/package/@glinr/theauth"><img src="https://img.shields.io/npm/dm/@glinr/theauth?style=flat&colorA=000000&colorB=000000&label=downloads" alt="monthly downloads" /></a>
  <a href="https://github.com/glincker/theauth/blob/main/LICENSE"><img src="https://img.shields.io/github/license/glincker/theauth?style=flat&colorA=000000&colorB=000000&label=license" alt="License" /></a>
  <a href="https://github.com/glincker/theauth/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/glincker/theauth/ci.yml?branch=main&style=flat&colorA=000000&colorB=000000&label=CI" alt="CI status" /></a>
  <a href="https://bundlephobia.com/package/@glinr/theauth"><img src="https://img.shields.io/bundlephobia/minzip/@glinr/theauth?style=flat&colorA=000000&colorB=000000&label=bundle" alt="bundle size" /></a>
  <a href="https://www.typescriptlang.org/"><img src="https://img.shields.io/badge/TypeScript-strict-blue?style=flat&colorA=000000&colorB=3178c6&logo=typescript&logoColor=white" alt="TypeScript strict" /></a>
  <a href="https://github.com/glincker/theauth/discussions"><img src="https://img.shields.io/github/discussions/glincker/theauth?style=flat&colorA=000000&colorB=000000&label=discussions" alt="GitHub Discussions" /></a>
  <a href="https://discord.gg/Ar5pcaZB99"><img src="https://img.shields.io/discord/829168897080557579?style=flat-square&logo=discord&logoColor=white&label=discord&color=5865F2" alt="Discord" /></a>
</p>

<p align="center">
  <a href="https://theauth.dev"><strong>Website</strong></a> &middot;
  <a href="https://docs.theauth.dev/quickstart"><strong>Quickstart</strong></a> &middot;
  <a href="https://docs.theauth.dev"><strong>Docs</strong></a> &middot;
  <a href="https://github.com/glincker/theauth/tree/main/examples"><strong>Examples</strong></a> &middot;
  <a href="https://github.com/glincker/theauth/discussions"><strong>Discussions</strong></a> &middot;
  <a href="#packages"><strong>Packages</strong></a> &middot;
  <a href="https://theauth.dev/pricing/"><strong>Cloud (early access)</strong></a>
</p>

<p align="center">
  <a href="https://theauth.dev">
    <img src="https://theauth.dev/og.png" alt="theAuth, auth OS for AI agents and humans" width="960" />
  </a>
</p>

<p align="center">
  <sub>TypeScript (<code>@glinr/theauth</code>) &middot; Go (<code>theauth-go</code>) &middot; Python and Terraform SDKs &middot; MIT licensed</sub>
</p>

---

## Why theAuth

Most auth libraries stop at human sign-in. That leaves you stitching together separate systems when your AI agents need identity, scoped permissions, delegation, and audit trails. theAuth handles both in one place.

### Agent identity

Cryptographic bearer tokens (`kv_...`), wildcard permission matching, delegation chains with depth limits, budget policies, a denial-history trust score, and CIBA-style approval flows.

### Human auth

14 methods: email/password, magic link, email OTP, phone SMS, passkey/WebAuthn, TOTP 2FA, anonymous, Google One-tap, Sign In With Ethereum, device authorization, username/password, captcha, password reset, session freshness.

### OAuth

17 first-class providers: Apple, Atlassian, Discord, Dropbox, Figma, GitHub, GitLab, Google, LinkedIn, Microsoft, Notion, Reddit, Slack, Spotify, Twitch, Twitter/X, Zoom. Plus a generic OIDC factory for anything else.

### MCP OAuth 2.1

Authorization server for the Model Context Protocol. PKCE S256, RFC 9728 / 8707 / 8414 / 7591.

### Enterprise

Organizations with RBAC, SAML 2.0 and OIDC SSO, admin controls (ban/impersonate), API key management, SCIM directory sync, multi-tenant isolation, GDPR export/delete/anonymize, audit evidence export mapped to EU AI Act, NIST, SOC 2, and ISO 42001 controls (not a certification).

### Runs on the edge

Works on Cloudflare Workers, Deno, and Bun without code changes. Three runtime dependencies: `drizzle-orm`, `jose`, `zod`.

### Security

Rate limiting per agent and per IP, HIBP password breach checking, CSRF protection, httpOnly secure cookies, email enumeration prevention, trusted device windows, signed expiring reset tokens, session freshness enforcement.

### Performance

The policy engine hits 2.6M warm-cache evals/sec with a p99 of 500ns. Cold paths stay under 0.3ms p99 on direct permissions, RBAC role expansion, and ReBAC graph lookups. Numbers from `pnpm bench` on the `policy-engine` suite in `packages/core/bench/`, reproducible locally.

---

## Install

```bash
npm install @glinr/theauth
# or
pnpm add @glinr/theauth
# or
yarn add @glinr/theauth
```

```typescript
import { Hono } from "hono";
import { createTheAuth } from "@glinr/theauth";
import { theAuthHono } from "@glinr/theauth-hono";

const auth = await createTheAuth({
  database: { provider: "postgres", url: process.env.DATABASE_URL! },
});

const app = new Hono();
app.route("/api/theauth", theAuthHono(auth));

// Create an AI agent with scoped MCP permissions
const agent = await auth.agent.create({
  ownerId: "user-123",
  name: "github-reader",
  type: "autonomous",
  permissions: [{ resource: "mcp:github:*", actions: ["read"] }],
});

const result = await auth.authorize(agent.id, {
  action: "read",
  resource: "mcp:github:repos",
});
// { allowed: true, auditId: "aud_..." }
```

---

### Quickstart: two tracks

Use either track alone or both together. Each runs as pasted with SQLite.

**Add agent auth** (identity, permissions, audit):

```typescript
import { createTheAuth, users } from "@glinr/theauth";

const auth = await createTheAuth({ database: { provider: "sqlite", url: ":memory:" } });

// Agents need an owner row in theauth_users (human auth creates these for you).
auth.db.insert(users).values({
  id: "user-123", email: "owner@example.com", name: "Owner",
  createdAt: new Date(), updatedAt: new Date(),
}).run();

const agent = await auth.agent.create({
  ownerId: "user-123",
  name: "github-reader",
  type: "autonomous",
  permissions: [{ resource: "mcp:github:*", actions: ["read"] }],
});
console.log(agent.token); // "kv_..." shown once

const { allowed } = await auth.authorize(agent.id, { action: "read", resource: "mcp:github:repos" });
```

Agent tokens start with `kv_`. That prefix is deliberate: it predates the rename from Kavach and was kept so already-issued tokens keep working ([RENAME-MAP.md](RENAME-MAP.md)).

**Add human auth** (email and password; `pnpm add @glinr/theauth-email`):

```typescript
import { createTheAuth } from "@glinr/theauth";
import { emailPassword } from "@glinr/theauth-email";

const auth = await createTheAuth({
  database: { provider: "sqlite", url: ":memory:" },
  plugins: [
    emailPassword({
      appUrl: "http://localhost:3000",
      sendVerificationEmail: async (email, _token, url) => console.log(email, url),
      sendResetEmail: async (email, _token, url) => console.log(email, url),
    }),
  ],
});

// Mount with an adapter, or call it directly:
const res = await auth.plugins.handleRequest(request); // POST /auth/sign-up, /auth/sign-in, ...
```

Full walkthrough: [docs.theauth.dev/quickstart](https://docs.theauth.dev/quickstart).

---

## How theAuth compares

Checked against each vendor's public docs on 2026-10-07. Vendors change fast, so verify against their docs. Full write-ups with sources: https://theauth.dev/compare/

| Capability | Auth0 | Clerk | Better Auth | **theAuth** |
|---|---|---|---|---|
| Source license | Proprietary | Proprietary | MIT | **MIT** |
| Self-hostable | Managed private cloud only | No | Yes | **Yes** |
| OAuth 2.1 server for MCP | Yes | Yes | Yes | **Yes** |
| Agent identity as its own model | Add-on: Token Vault, CIBA | Not found in docs | Plugin, not yet stable | **Yes, core** |
| Enterprise SSO | Yes | Yes | Plugin | **SAML 2.0, OIDC, SCIM** |

---

## Packages

Every published package lives in this monorepo. Versions below are live from npm.

| Package | What it is | npm | Source | Docs |
|---|---|---|---|---|
| **Core** | | | | |
| `@glinr/theauth` | The auth OS for AI agents: identity, permissions, delegation, and audit for the agentic era | [npm](https://www.npmjs.com/package/@glinr/theauth) ![npm](https://img.shields.io/npm/v/@glinr/theauth) | [source](https://github.com/glincker/theauth/tree/main/packages/core) | [docs](https://docs.theauth.dev/concepts) |
| `@glinr/theauth-email` | Email and password authentication for TheAuth | [npm](https://www.npmjs.com/package/@glinr/theauth-email) ![npm](https://img.shields.io/npm/v/@glinr/theauth-email) | [source](https://github.com/glincker/theauth/tree/main/packages/auth/email) | [docs](https://docs.theauth.dev/auth/email-password) |
| `@glinr/theauth-plugin-discovery` | A2A agent capability card discovery plugin for TheAuth | [npm](https://www.npmjs.com/package/@glinr/theauth-plugin-discovery) ![npm](https://img.shields.io/npm/v/@glinr/theauth-plugin-discovery) | [source](https://github.com/glincker/theauth/tree/main/packages/plugins/discovery) | [docs](https://docs.theauth.dev/a2a) |
| `@glinr/theauth-plugin-telemetry` | OpenTelemetry integration plugin for TheAuth: converts auth events into OTel spans | [npm](https://www.npmjs.com/package/@glinr/theauth-plugin-telemetry) ![npm](https://img.shields.io/npm/v/@glinr/theauth-plugin-telemetry) | [source](https://github.com/glincker/theauth/tree/main/packages/plugins/telemetry) |  |
| **Client and UI** | | | | |
| `@glinr/theauth-client` | TypeScript client for the TheAuth REST API | [npm](https://www.npmjs.com/package/@glinr/theauth-client) ![npm](https://img.shields.io/npm/v/@glinr/theauth-client) | [source](https://github.com/glincker/theauth/tree/main/packages/client) | [docs](https://docs.theauth.dev/client-sdk) |
| `@glinr/theauth-dashboard` | TheAuth admin dashboard: React UI for managing agents, permissions, and audit logs | [npm](https://www.npmjs.com/package/@glinr/theauth-dashboard) ![npm](https://img.shields.io/npm/v/@glinr/theauth-dashboard) | [source](https://github.com/glincker/theauth/tree/main/packages/dashboard) | [docs](https://docs.theauth.dev/dashboard) |
| `@glinr/theauth-electron` | TheAuth auth client for Electron desktop apps | [npm](https://www.npmjs.com/package/@glinr/theauth-electron) ![npm](https://img.shields.io/npm/v/@glinr/theauth-electron) | [source](https://github.com/glincker/theauth/tree/main/packages/electron) | [docs](https://docs.theauth.dev/electron) |
| `@glinr/theauth-expo` | React Native / Expo client for TheAuth auth | [npm](https://www.npmjs.com/package/@glinr/theauth-expo) ![npm](https://img.shields.io/npm/v/@glinr/theauth-expo) | [source](https://github.com/glincker/theauth/tree/main/packages/expo) | [docs](https://docs.theauth.dev/expo) |
| `@glinr/theauth-react` | React hooks for TheAuth auth (with v0.5 session rotation) | [npm](https://www.npmjs.com/package/@glinr/theauth-react) ![npm](https://img.shields.io/npm/v/@glinr/theauth-react) | [source](https://github.com/glincker/theauth/tree/main/packages/react) | [docs](https://docs.theauth.dev/react) |
| `@glinr/theauth-svelte` | Svelte stores for TheAuth auth | [npm](https://www.npmjs.com/package/@glinr/theauth-svelte) ![npm](https://img.shields.io/npm/v/@glinr/theauth-svelte) | [source](https://github.com/glincker/theauth/tree/main/packages/svelte) | [docs](https://docs.theauth.dev/svelte) |
| `@glinr/theauth-ui` | Pre-built auth UI components for TheAuth | [npm](https://www.npmjs.com/package/@glinr/theauth-ui) ![npm](https://img.shields.io/npm/v/@glinr/theauth-ui) | [source](https://github.com/glincker/theauth/tree/main/packages/ui) | [docs](https://docs.theauth.dev/ui-components) |
| `@glinr/theauth-ui-headless` | Unstyled, accessible account components for TheAuth: sessions, API and agent tokens, device approval, step-up | [npm](https://www.npmjs.com/package/@glinr/theauth-ui-headless) ![npm](https://img.shields.io/npm/v/@glinr/theauth-ui-headless) | [source](https://github.com/glincker/theauth/tree/main/packages/ui-headless) | [docs](https://docs.theauth.dev/ui-components) |
| `@glinr/theauth-vue` | Vue 3 composables for TheAuth auth | [npm](https://www.npmjs.com/package/@glinr/theauth-vue) ![npm](https://img.shields.io/npm/v/@glinr/theauth-vue) | [source](https://github.com/glincker/theauth/tree/main/packages/vue) | [docs](https://docs.theauth.dev/vue) |
| **Framework adapters** | | | | |
| `@glinr/theauth-astro` | Astro adapter for TheAuth: exposes agent auth as HTTP REST endpoints | [npm](https://www.npmjs.com/package/@glinr/theauth-astro) ![npm](https://img.shields.io/npm/v/@glinr/theauth-astro) | [source](https://github.com/glincker/theauth/tree/main/packages/adapters/astro) | [docs](https://docs.theauth.dev/adapters/astro) |
| `@glinr/theauth-express` | Express adapter for TheAuth: exposes agent auth as HTTP REST endpoints | [npm](https://www.npmjs.com/package/@glinr/theauth-express) ![npm](https://img.shields.io/npm/v/@glinr/theauth-express) | [source](https://github.com/glincker/theauth/tree/main/packages/adapters/express) | [docs](https://docs.theauth.dev/adapters/express) |
| `@glinr/theauth-fastify` | Fastify adapter for TheAuth: exposes agent auth as HTTP REST endpoints | [npm](https://www.npmjs.com/package/@glinr/theauth-fastify) ![npm](https://img.shields.io/npm/v/@glinr/theauth-fastify) | [source](https://github.com/glincker/theauth/tree/main/packages/adapters/fastify) | [docs](https://docs.theauth.dev/adapters/fastify) |
| `@glinr/theauth-hono` | Hono adapter for TheAuth: exposes agent auth as HTTP REST endpoints | [npm](https://www.npmjs.com/package/@glinr/theauth-hono) ![npm](https://img.shields.io/npm/v/@glinr/theauth-hono) | [source](https://github.com/glincker/theauth/tree/main/packages/adapters/hono) | [docs](https://docs.theauth.dev/adapters/hono) |
| `@glinr/theauth-nestjs` | NestJS adapter for TheAuth | [npm](https://www.npmjs.com/package/@glinr/theauth-nestjs) ![npm](https://img.shields.io/npm/v/@glinr/theauth-nestjs) | [source](https://github.com/glincker/theauth/tree/main/packages/adapters/nestjs) | [docs](https://docs.theauth.dev/adapters/nestjs) |
| `@glinr/theauth-nextjs` | Next.js App Router adapter for TheAuth: exposes agent auth as HTTP REST endpoints | [npm](https://www.npmjs.com/package/@glinr/theauth-nextjs) ![npm](https://img.shields.io/npm/v/@glinr/theauth-nextjs) | [source](https://github.com/glincker/theauth/tree/main/packages/adapters/nextjs) | [docs](https://docs.theauth.dev/adapters/nextjs) |
| `@glinr/theauth-nextjs-auth` | Next.js adapter for TheAuth-style external auth backends: cookies, refresh, CSRF, getServerSession, middleware. | [npm](https://www.npmjs.com/package/@glinr/theauth-nextjs-auth) ![npm](https://img.shields.io/npm/v/@glinr/theauth-nextjs-auth) | [source](https://github.com/glincker/theauth/tree/main/packages/adapters/nextjs-auth) |  |
| `@glinr/theauth-nuxt` | Nuxt adapter for TheAuth: exposes agent auth as HTTP REST endpoints via H3 | [npm](https://www.npmjs.com/package/@glinr/theauth-nuxt) ![npm](https://img.shields.io/npm/v/@glinr/theauth-nuxt) | [source](https://github.com/glincker/theauth/tree/main/packages/adapters/nuxt) | [docs](https://docs.theauth.dev/adapters/nuxt) |
| `@glinr/theauth-solidstart` | SolidStart adapter for TheAuth | [npm](https://www.npmjs.com/package/@glinr/theauth-solidstart) ![npm](https://img.shields.io/npm/v/@glinr/theauth-solidstart) | [source](https://github.com/glincker/theauth/tree/main/packages/adapters/solidstart) | [docs](https://docs.theauth.dev/adapters/solidstart) |
| `@glinr/theauth-sveltekit` | SvelteKit adapter for TheAuth: exposes agent auth as HTTP REST endpoints | [npm](https://www.npmjs.com/package/@glinr/theauth-sveltekit) ![npm](https://img.shields.io/npm/v/@glinr/theauth-sveltekit) | [source](https://github.com/glincker/theauth/tree/main/packages/adapters/sveltekit) | [docs](https://docs.theauth.dev/adapters/sveltekit) |
| `@glinr/theauth-tanstack` | TanStack Start adapter for TheAuth | [npm](https://www.npmjs.com/package/@glinr/theauth-tanstack) ![npm](https://img.shields.io/npm/v/@glinr/theauth-tanstack) | [source](https://github.com/glincker/theauth/tree/main/packages/adapters/tanstack) | [docs](https://docs.theauth.dev/adapters/tanstack) |
| **Database adapters** | | | | |
| `@glinr/theauth-prisma` | Prisma database adapter for TheAuth: use PrismaClient as your TheAuth database backend | [npm](https://www.npmjs.com/package/@glinr/theauth-prisma) ![npm](https://img.shields.io/npm/v/@glinr/theauth-prisma) | [source](https://github.com/glincker/theauth/tree/main/packages/adapters/prisma) | [docs](https://docs.theauth.dev/prisma) |
| **Tooling and CLI** | | | | |
| `@glinr/create-theauth-app` | Scaffold a TheAuth-powered app in seconds | [npm](https://www.npmjs.com/package/@glinr/create-theauth-app) ![npm](https://img.shields.io/npm/v/@glinr/create-theauth-app) | [source](https://github.com/glincker/theauth/tree/main/packages/create-theauth-app) | [docs](https://docs.theauth.dev/quickstart) |
| `@glinr/theauth-cli` | TheAuth CLI: setup wizard, dashboard launcher, and development tools | [npm](https://www.npmjs.com/package/@glinr/theauth-cli) ![npm](https://img.shields.io/npm/v/@glinr/theauth-cli) | [source](https://github.com/glincker/theauth/tree/main/packages/cli) |  |
| `@glinr/theauth-gateway` | Standalone auth proxy for TheAuth: enforces auth, authorization, and audit in front of any API or MCP server | [npm](https://www.npmjs.com/package/@glinr/theauth-gateway) ![npm](https://img.shields.io/npm/v/@glinr/theauth-gateway) | [source](https://github.com/glincker/theauth/tree/main/packages/gateway) | [docs](https://docs.theauth.dev/gateway) |
| `@glinr/theauth-test-utils` | Test utilities for TheAuth: mock providers, factories, and assertions for auth test suites | [npm](https://www.npmjs.com/package/@glinr/theauth-test-utils) ![npm](https://img.shields.io/npm/v/@glinr/theauth-test-utils) | [source](https://github.com/glincker/theauth/tree/main/packages/test-utils) | [docs](https://docs.theauth.dev/test-utils) |
| **Other SDKs** | | | | |
| `theauth-go` | Go SDK and server toolkit: agent identity, OAuth 2.1, MCP resource server | [pkg.go.dev](https://pkg.go.dev/github.com/glincker/theauth-go/v2) | [theauth-go](https://github.com/glincker/theauth-go), [all Go packages](https://github.com/glincker/theauth-go#packages) | [Go docs](https://docs.theauth.dev/go) |
| `theauth (Python)` | Python SDK for theAuth | [PyPI](https://pypi.org/project/theauth/) ![PyPI](https://img.shields.io/pypi/v/theauth) | [sdks/python](https://github.com/glincker/theauth/tree/main/sdks/python) |  |
| `terraform-provider-theauth` | Terraform provider for agents, permissions, API keys, and organizations | [Registry](https://registry.terraform.io/providers/glincker/theauth) | [sdks/terraform](https://github.com/glincker/theauth/tree/main/sdks/terraform) | [Docs](https://docs.theauth.dev/terraform) |

---

## Features

<details>
<summary><strong>Full feature checklist (click to expand)</strong></summary>

### Authentication

- Email and password with HIBP breach checking
- Magic link
- Email OTP
- Phone SMS OTP
- Passkeys / WebAuthn
- TOTP 2FA (authenticator apps)
- SAML 2.0 and OIDC SSO
- Anonymous sessions
- Google One Tap
- Sign In With Ethereum
- Device Authorization (TV / CLI flows)
- Username and password
- Captcha integration
- Session freshness enforcement

### OAuth 2.1

- Authorization Code + PKCE
- Client Credentials
- Device Authorization Grant
- Refresh Token rotation
- Token introspection
- Dynamic Client Registration (RFC 7591)
- Server metadata (RFC 8414)
- Resource indicators (RFC 8707)
- Authorization Server Issuer Identification (RFC 9728)

### MCP Support

- Full OAuth 2.1 authorization server for the Model Context Protocol
- PKCE S256 mandatory
- RFC 9728 / 8707 / 8414 / 7591 compliant
- Agent token issuance and validation

### AI Agent Identity

- Cryptographic bearer tokens (`kv_...`)
- Wildcard permission matching
- Delegation chains with configurable depth limits
- Budget policies per agent
- Denial-based trust scoring (no built-in anomaly detector)
- CIBA-style approval flows for sensitive tool calls
- Full audit trail per agent action

### Framework Adapters

- Next.js 15 (App Router, Route Handlers, Middleware)
- SvelteKit
- Nuxt / Vue
- Hono (Cloudflare Workers, Bun, Deno)
- Express
- Fastify
- Astro
- NestJS
- SolidStart
- TanStack Start
- React Native / Expo
- Electron

### Database Adapters

Built-in: SQLite, PostgreSQL, MySQL, Cloudflare D1

Plugin: Prisma (share an existing PrismaClient)

### Enterprise

- Organizations with RBAC
- SCIM directory sync
- Admin controls (ban, impersonate)
- API key management
- Multi-tenant isolation
- GDPR: export, delete, anonymize
- Compliance mapping and evidence export (JSON, CSV, verifiable credentials) for EU AI Act, NIST, SOC 2, ISO 42001. Not a certification

### Edge Runtimes

- Cloudflare Workers (D1, KV)
- Vercel Edge Functions
- Deno Deploy
- Bun
- Three runtime dependencies: `drizzle-orm`, `jose`, `zod`

</details>

---

## Quick start by framework

<details>
<summary><strong>Next.js (App Router)</strong></summary>

```bash
npm install @glinr/theauth @glinr/theauth-nextjs
```

```typescript
// app/api/theauth/[...theauth]/route.ts
import { createTheAuth } from "@glinr/theauth";
import { theAuthNextjs } from "@glinr/theauth-nextjs";

const auth = await createTheAuth({
  database: { provider: "postgres", url: process.env.DATABASE_URL! },
});

export const { GET, POST, PATCH, DELETE, OPTIONS } = theAuthNextjs(auth);
```

The adapter serves the agent, authorization, delegation, and audit routes under `/api/theauth`. Human sign-in is not wired by the adapter: see the docs for the auth methods you enable.

See [`examples/nextjs-app`](https://github.com/glincker/theauth/tree/main/examples/nextjs-app) for a full working example.

</details>

<details>
<summary><strong>SvelteKit</strong></summary>

```bash
npm install @glinr/theauth @glinr/theauth-sveltekit
```

```typescript
// src/routes/api/theauth/[...path]/+server.ts
import { createTheAuth } from "@glinr/theauth";
import { theAuthSvelteKit } from "@glinr/theauth-sveltekit";

const auth = await createTheAuth({
  database: { provider: "sqlite", url: "theauth.db" },
});

export const { GET, POST, PATCH, DELETE, OPTIONS } = theAuthSvelteKit(auth);
```

</details>

<details>
<summary><strong>Nuxt</strong></summary>

```bash
npm install @glinr/theauth @glinr/theauth-nuxt
```

```typescript
// server/api/theauth/[...].ts
import { createTheAuth } from "@glinr/theauth";
import { theAuthNuxt } from "@glinr/theauth-nuxt";

const auth = await createTheAuth({
  database: { provider: "postgres", url: process.env.DATABASE_URL! },
});

export default theAuthNuxt(auth);
```

</details>

<details>
<summary><strong>Hono (Cloudflare Workers / Express / Bun)</strong></summary>

```bash
npm install @glinr/theauth @glinr/theauth-hono
```

```typescript
import { Hono } from "hono";
import { createTheAuth } from "@glinr/theauth";
import { theAuthHono } from "@glinr/theauth-hono";

const auth = await createTheAuth({
  database: { provider: "postgres", url: process.env.DATABASE_URL! },
});

const app = new Hono();
app.route("/api/theauth", theAuthHono(auth));

export default app;
```

See [`examples/hono-server`](https://github.com/glincker/theauth/tree/main/examples/hono-server) and [`examples/cloudflare-workers`](https://github.com/glincker/theauth/tree/main/examples/cloudflare-workers).

</details>

---

## Documentation

**Primary docs:** [docs.theauth.dev](https://docs.theauth.dev)

| Section | Link | What you will find |
|---|---|---|
| Getting Started | [docs.theauth.dev/quickstart](https://docs.theauth.dev/quickstart) | Installation, first auth flow |
| Authentication | [docs.theauth.dev/auth](https://docs.theauth.dev/auth) | All auth methods and plugins |
| Agent Identity | [docs.theauth.dev/agents](https://docs.theauth.dev/agents) | Agent tokens, delegation, policies |
| Permissions | [docs.theauth.dev/permissions](https://docs.theauth.dev/permissions) | RBAC, wildcard matching, ReBAC |
| MCP OAuth 2.1 | [docs.theauth.dev/mcp](https://docs.theauth.dev/mcp) | MCP auth server setup |
| Framework Adapters | [docs.theauth.dev/adapters](https://docs.theauth.dev/adapters) | Next.js, Hono, SvelteKit, etc. |
| API Reference | [docs.theauth.dev/api](https://docs.theauth.dev/api) | Config, types, errors |
| Security | [SECURITY.md](SECURITY.md) | Threat model, disclosure policy |

---

## Adapters

Framework and database adapters are listed in [Packages](#packages) above. SQLite, PostgreSQL, MySQL and Cloudflare D1 are built into the core package; use `@glinr/theauth-prisma` to share an existing PrismaClient.

---

## Example apps

| Example | What it shows | Directory |
|---|---|---|
| `nextjs-app` | Full Next.js 15 App Router integration | [`examples/nextjs-app`](https://github.com/glincker/theauth/tree/main/examples/nextjs-app) |
| `nextjs-demo` | UI components + sign-in flows | [`examples/nextjs-demo`](https://github.com/glincker/theauth/tree/main/examples/nextjs-demo) |
| `hono-server` | Standalone Hono API with auth | [`examples/hono-server`](https://github.com/glincker/theauth/tree/main/examples/hono-server) |
| `cloudflare-workers` | Workers + D1 database | [`examples/cloudflare-workers`](https://github.com/glincker/theauth/tree/main/examples/cloudflare-workers) |
| `mcp-server` | MCP OAuth 2.1 authorization server | [`examples/mcp-server`](https://github.com/glincker/theauth/tree/main/examples/mcp-server) |
| `scim-okta` | SCIM directory sync with Okta | [`examples/scim-okta`](https://github.com/glincker/theauth/tree/main/examples/scim-okta) |
| `basic-agent` | AI agent token issuance and policy | [`examples/basic-agent`](https://github.com/glincker/theauth/tree/main/examples/basic-agent) |
| `migrate-from-auth0` | Step-by-step Auth0 migration | [`examples/migrate-from-auth0`](https://github.com/glincker/theauth/tree/main/examples/migrate-from-auth0) |
| `migrate-from-better-auth-agent-plugin` | Migration from better-auth agent plugin | [`examples/migrate-from-better-auth-agent-plugin`](https://github.com/glincker/theauth/tree/main/examples/migrate-from-better-auth-agent-plugin) |

---

## theAuth Cloud

Hosted version with dashboard, billing, and zero infrastructure. Early access: [theauth.dev/pricing](https://theauth.dev/pricing/)

| Plan | MAU | Price |
|---|---|---|
| Free | 1,000 | $0 |
| Starter | 10,000 | $29/mo |
| Growth | 50,000 | $79/mo |
| Scale | 200,000 | $199/mo |
| Enterprise | Custom | Custom |

---

---

## Security

Responsible disclosure: see [SECURITY.md](SECURITY.md). Do not open a public issue for vulnerabilities.

---

## Roadmap

Follow development on [GitHub Discussions](https://github.com/glincker/theauth/discussions) and the [changelog](CHANGELOG.md).

---

## Community

Join the GLINR Discord and talk to us in the `#theauth` forum channel.

<a href="https://discord.gg/Ar5pcaZB99"><img src="https://discord.com/api/guilds/829168897080557579/widget.png?style=banner2" alt="Join the GLINR Discord" /></a>

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). First-time contributor? Look for issues labeled `good first issue`.

By contributing, you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).

---

## License

[MIT](LICENSE) (c) 2026 TheAuth

---

## Made by GLINCKER, a GLINR STUDIOS company

theAuth is built and maintained in the open by [GLINCKER](https://glincker.com), the open-source division of [GLINR STUDIOS](https://glinr.com). Founder: [thegdsks.com](https://thegdsks.com). This site and the docs are designed with [GLINUI](https://glinui.com).

### Partner open-source projects

| Project | What it is | Site | Source |
|---|---|---|---|
| **LevelRail** | Self-hosted deployment platform: push to git, get a running app. | [levelrail.com](https://levelrail.com) | [glincker/levelrail](https://github.com/glincker/levelrail) |
| **theSVG** | Open-source brand SVG icons. The brand marks on theauth.dev come from it. | [thesvg.org](https://thesvg.org) | [glincker/thesvg](https://github.com/glincker/thesvg) |
| **GLINUI** | Open-source liquid glass UI components for React. theauth.dev is designed with it. | [glinui.com](https://glinui.com) | [glincker/glinui](https://github.com/glincker/glinui) |

<p align="center">
  <em>By <a href="https://glincker.com"><strong>GLINCKER</strong></a>, a <a href="https://glinr.com">GLINR STUDIOS</a> company. Founded by <a href="https://thegdsks.com">thegdsks</a>.</em>
</p>
