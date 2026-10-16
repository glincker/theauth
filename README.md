<p align="center">
  <img src="https://theauth.dev/logo.svg" height="64" alt="theAuth" />
</p>

<h1 align="center">theAuth</h1>

<p align="center"><strong>Open-source auth for AI agents and humans.</strong><br>
Agent identity, delegation, an MCP OAuth 2.1 server, DPoP, passkeys, SSO and SCIM in one TypeScript library. Self-hosted, MIT licensed, with Go and Python SDKs.</p>

<p align="center">
  <a href="https://www.npmjs.com/package/@glinr/theauth"><img src="https://img.shields.io/npm/v/@glinr/theauth?style=flat&colorA=000000&colorB=000000&label=npm" alt="npm version" /></a>
  <a href="https://github.com/glincker/theauth/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/glincker/theauth/ci.yml?branch=main&style=flat&colorA=000000&colorB=000000&label=CI" alt="CI status" /></a>
  <a href="https://github.com/glincker/theauth/blob/main/LICENSE"><img src="https://img.shields.io/github/license/glincker/theauth?style=flat&colorA=000000&colorB=000000&label=license" alt="License" /></a>
  <a href="https://discord.gg/Ar5pcaZB99"><img src="https://img.shields.io/discord/829168897080557579?style=flat-square&logo=discord&logoColor=white&label=discord&color=5865F2" alt="Discord" /></a>
  <a href="https://context7.com/glincker/theauth"><img src="https://img.shields.io/badge/context7-indexed-000000?style=flat&colorA=000000&colorB=000000" alt="Context7" /></a>
  <a href="https://github.com/glincker/theauth/actions/workflows/codeql.yml"><img src="https://github.com/glincker/theauth/actions/workflows/codeql.yml/badge.svg" alt="CodeQL" /></a>
  <a href="https://codecov.io/gh/glincker/theauth"><img src="https://img.shields.io/codecov/c/github/glincker/theauth?style=flat&colorA=000000&colorB=000000&label=coverage" alt="Code coverage" /></a>
</p>

<p align="center">
  <a href="https://theauth.dev"><strong>Website</strong></a> &middot;
  <a href="https://docs.theauth.dev/quickstart"><strong>Quickstart</strong></a> &middot;
  <a href="https://docs.theauth.dev"><strong>Docs</strong></a> &middot;
  <a href="https://github.com/glincker/theauth/tree/main/examples"><strong>Examples</strong></a> &middot;
  <a href="https://github.com/glincker/theauth/discussions"><strong>Discussions</strong></a> &middot;
  <a href="https://discord.gg/Ar5pcaZB99"><strong>GLINR Discord</strong></a>
</p>

<p align="center">
  <a href="https://theauth.dev">
    <img src="https://theauth.dev/og.png" alt="theAuth, open-source auth for AI agents and humans" width="720" />
  </a>
</p>

---

## What it is

Most auth libraries stop at human sign-in. Once an AI agent needs its own identity, scoped permissions, delegation from a user, and an audit trail, you end up bolting a second system on. theAuth puts agents and humans in one library: sign-in methods, an OAuth 2.1 authorization server for MCP, and agent tokens with permissions you can check and audit.

It runs on Node, Bun, Deno and Cloudflare Workers with three runtime dependencies (`drizzle-orm`, `jose`, `zod`). MIT licensed. No hosted service required.

theAuth implements OAuth 2.1 with PKCE, DPoP, MCP authorization and OpenID Connect, with about 3,900 test cases and CodeQL on every pull request. Versions below 1.0 can still change between minor releases, and the changelog lists every breaking change. The project was called kavachOS until 2026: see the [rename map](RENAME-MAP.md) if you have older code.

## Works with

<p align="center">
  <a href="https://docs.theauth.dev/works-with" title="GitHub"><picture><source media="(prefers-color-scheme: dark)" srcset="docs/brand-icons/works-with/github-dark.svg"><img src="docs/brand-icons/works-with/github.svg" alt="GitHub" height="32" width="32"></picture></a>
  &nbsp;&nbsp;<a href="https://docs.theauth.dev/works-with" title="Google"><picture><source media="(prefers-color-scheme: dark)" srcset="docs/brand-icons/works-with/google-dark.svg"><img src="docs/brand-icons/works-with/google.svg" alt="Google" height="32" width="32"></picture></a>
  &nbsp;&nbsp;<a href="https://docs.theauth.dev/works-with" title="Apple"><picture><source media="(prefers-color-scheme: dark)" srcset="docs/brand-icons/works-with/apple-dark.svg"><img src="docs/brand-icons/works-with/apple.svg" alt="Apple" height="32" width="32"></picture></a>
  &nbsp;&nbsp;<a href="https://docs.theauth.dev/works-with" title="Microsoft"><picture><source media="(prefers-color-scheme: dark)" srcset="docs/brand-icons/works-with/microsoft-dark.svg"><img src="docs/brand-icons/works-with/microsoft.svg" alt="Microsoft" height="32" width="32"></picture></a>
  &nbsp;&nbsp;<a href="https://docs.theauth.dev/works-with" title="Discord"><picture><source media="(prefers-color-scheme: dark)" srcset="docs/brand-icons/works-with/discord-dark.svg"><img src="docs/brand-icons/works-with/discord.svg" alt="Discord" height="32" width="32"></picture></a>
  &nbsp;&nbsp;<a href="https://docs.theauth.dev/works-with" title="GitLab"><picture><source media="(prefers-color-scheme: dark)" srcset="docs/brand-icons/works-with/gitlab-dark.svg"><img src="docs/brand-icons/works-with/gitlab.svg" alt="GitLab" height="32" width="32"></picture></a>
  &nbsp;&nbsp;<a href="https://docs.theauth.dev/works-with" title="Slack"><picture><source media="(prefers-color-scheme: dark)" srcset="docs/brand-icons/works-with/slack-dark.svg"><img src="docs/brand-icons/works-with/slack.svg" alt="Slack" height="32" width="32"></picture></a>
  &nbsp;&nbsp;<a href="https://docs.theauth.dev/works-with" title="LinkedIn"><picture><source media="(prefers-color-scheme: dark)" srcset="docs/brand-icons/works-with/linkedin-dark.svg"><img src="docs/brand-icons/works-with/linkedin.svg" alt="LinkedIn" height="32" width="32"></picture></a>
  &nbsp;&nbsp;<a href="https://docs.theauth.dev/works-with" title="Auth0"><picture><source media="(prefers-color-scheme: dark)" srcset="docs/brand-icons/works-with/auth0-dark.svg"><img src="docs/brand-icons/works-with/auth0.svg" alt="Auth0" height="32" width="32"></picture></a>
  &nbsp;&nbsp;<a href="https://docs.theauth.dev/works-with" title="Okta"><picture><source media="(prefers-color-scheme: dark)" srcset="docs/brand-icons/works-with/okta-dark.svg"><img src="docs/brand-icons/works-with/okta.svg" alt="Okta" height="32" width="32"></picture></a>
  &nbsp;&nbsp;<a href="https://docs.theauth.dev/works-with" title="Keycloak"><picture><source media="(prefers-color-scheme: dark)" srcset="docs/brand-icons/works-with/keycloak-dark.svg"><img src="docs/brand-icons/works-with/keycloak.svg" alt="Keycloak" height="32" width="32"></picture></a>
  &nbsp;&nbsp;<a href="https://docs.theauth.dev/works-with" title="Next.js"><picture><source media="(prefers-color-scheme: dark)" srcset="docs/brand-icons/works-with/nextjs-dark.svg"><img src="docs/brand-icons/works-with/nextjs.svg" alt="Next.js" height="32" width="32"></picture></a>
  &nbsp;&nbsp;<a href="https://docs.theauth.dev/works-with" title="Hono"><picture><source media="(prefers-color-scheme: dark)" srcset="docs/brand-icons/works-with/hono-dark.svg"><img src="docs/brand-icons/works-with/hono.svg" alt="Hono" height="32" width="32"></picture></a>
  &nbsp;&nbsp;<a href="https://docs.theauth.dev/works-with" title="Express"><picture><source media="(prefers-color-scheme: dark)" srcset="docs/brand-icons/works-with/express-dark.svg"><img src="docs/brand-icons/works-with/express.svg" alt="Express" height="32" width="32"></picture></a>
  &nbsp;&nbsp;<a href="https://docs.theauth.dev/works-with" title="Fastify"><picture><source media="(prefers-color-scheme: dark)" srcset="docs/brand-icons/works-with/fastify-dark.svg"><img src="docs/brand-icons/works-with/fastify.svg" alt="Fastify" height="32" width="32"></picture></a>
  &nbsp;&nbsp;<a href="https://docs.theauth.dev/works-with" title="NestJS"><picture><source media="(prefers-color-scheme: dark)" srcset="docs/brand-icons/works-with/nestjs-dark.svg"><img src="docs/brand-icons/works-with/nestjs.svg" alt="NestJS" height="32" width="32"></picture></a>
  &nbsp;&nbsp;<a href="https://docs.theauth.dev/works-with" title="Nuxt"><picture><source media="(prefers-color-scheme: dark)" srcset="docs/brand-icons/works-with/nuxt-dark.svg"><img src="docs/brand-icons/works-with/nuxt.svg" alt="Nuxt" height="32" width="32"></picture></a>
  &nbsp;&nbsp;<a href="https://docs.theauth.dev/works-with" title="SvelteKit"><picture><source media="(prefers-color-scheme: dark)" srcset="docs/brand-icons/works-with/sveltekit-dark.svg"><img src="docs/brand-icons/works-with/sveltekit.svg" alt="SvelteKit" height="32" width="32"></picture></a>
  &nbsp;&nbsp;<a href="https://docs.theauth.dev/works-with" title="Astro"><picture><source media="(prefers-color-scheme: dark)" srcset="docs/brand-icons/works-with/astro-dark.svg"><img src="docs/brand-icons/works-with/astro.svg" alt="Astro" height="32" width="32"></picture></a>
  &nbsp;&nbsp;<a href="https://docs.theauth.dev/works-with" title="React"><picture><source media="(prefers-color-scheme: dark)" srcset="docs/brand-icons/works-with/react-dark.svg"><img src="docs/brand-icons/works-with/react.svg" alt="React" height="32" width="32"></picture></a>
  &nbsp;&nbsp;<a href="https://docs.theauth.dev/works-with" title="Expo"><picture><source media="(prefers-color-scheme: dark)" srcset="docs/brand-icons/works-with/expo-dark.svg"><img src="docs/brand-icons/works-with/expo.svg" alt="Expo" height="32" width="32"></picture></a>
  &nbsp;&nbsp;<a href="https://docs.theauth.dev/works-with" title="Electron"><picture><source media="(prefers-color-scheme: dark)" srcset="docs/brand-icons/works-with/electron-dark.svg"><img src="docs/brand-icons/works-with/electron.svg" alt="Electron" height="32" width="32"></picture></a>
  &nbsp;&nbsp;<a href="https://docs.theauth.dev/works-with" title="PostgreSQL"><picture><source media="(prefers-color-scheme: dark)" srcset="docs/brand-icons/works-with/postgresql-dark.svg"><img src="docs/brand-icons/works-with/postgresql.svg" alt="PostgreSQL" height="32" width="32"></picture></a>
  &nbsp;&nbsp;<a href="https://docs.theauth.dev/works-with" title="MySQL"><picture><source media="(prefers-color-scheme: dark)" srcset="docs/brand-icons/works-with/mysql-dark.svg"><img src="docs/brand-icons/works-with/mysql.svg" alt="MySQL" height="32" width="32"></picture></a>
  &nbsp;&nbsp;<a href="https://docs.theauth.dev/works-with" title="SQLite"><picture><source media="(prefers-color-scheme: dark)" srcset="docs/brand-icons/works-with/sqlite-dark.svg"><img src="docs/brand-icons/works-with/sqlite.svg" alt="SQLite" height="32" width="32"></picture></a>
  &nbsp;&nbsp;<a href="https://docs.theauth.dev/works-with" title="MCP"><picture><source media="(prefers-color-scheme: dark)" srcset="docs/brand-icons/works-with/modelcontextprotocol-dark.svg"><img src="docs/brand-icons/works-with/modelcontextprotocol.svg" alt="MCP" height="32" width="32"></picture></a>
  &nbsp;&nbsp;<a href="https://docs.theauth.dev/works-with" title="Go"><picture><source media="(prefers-color-scheme: dark)" srcset="docs/brand-icons/works-with/go-dark.svg"><img src="docs/brand-icons/works-with/go.svg" alt="Go" height="32" width="32"></picture></a>
</p>

<sub>Logos from <a href="https://thesvg.org">theSVG</a>. All trademarks belong to their respective owners; shown to identify compatibility, no affiliation implied.</sub>

<p align="center"><a href="https://docs.theauth.dev/works-with">See everything theAuth works with</a>: 40 OAuth providers, ten framework adapters, four runtimes and the databases you already run.</p>

> Names and logos belong to their owners and are shown only to indicate compatibility.

## 30 second quickstart

Runs as pasted with SQLite. Needs Node 20 or newer.

```bash
npm install @glinr/theauth
```

```typescript
import { createTheAuth, users } from "@glinr/theauth";

const auth = await createTheAuth({
  database: { provider: "sqlite", url: ":memory:" },
  agents: { enabled: true }, // creates the agent and audit tables
});

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
console.log(allowed); // true
```

Agent tokens start with `kv_`. The prefix predates the rename from Kavach and stays so issued tokens keep working ([RENAME-MAP.md](RENAME-MAP.md)).

To mount it over HTTP, pick an adapter such as `@glinr/theauth-hono` or `@glinr/theauth-nextjs` (framework snippets below). To add email and password, install `@glinr/theauth-email`. Full walkthrough: [docs.theauth.dev/quickstart](https://docs.theauth.dev/quickstart). Or scaffold an app: `npm create @glinr/theauth-app`.

## What is merged today

| Area | What you get | Docs |
|---|---|---|
| Agent identity | `kv_` bearer tokens, wildcard permissions, delegation chains with depth limits, budget policies, denial-based trust score, CIBA-style approvals, audit trail per action | [Agents](https://docs.theauth.dev/agents) |
| MCP OAuth 2.1 server | Authorization code with PKCE S256, dynamic client registration, resource indicators, metadata (RFC 7591, 8707, 8414, 9728) | [MCP](https://docs.theauth.dev/mcp) |
| DPoP | Sender-constrained tokens for MCP resource servers | [DPoP](https://docs.theauth.dev/dpop) |
| Token vault | Encrypted third-party OAuth tokens for agents, refresh with a shared lock, key rotation | [Token vault](https://docs.theauth.dev/token-vault) |
| Human sign-in | Email and password (HIBP check), magic link, email OTP, phone OTP, passkeys, TOTP, anonymous, Google One Tap, SIWE, device flow, username, captcha | [Auth](https://docs.theauth.dev/auth) |
| Providers and presets | 17 first-class OAuth providers, a generic OIDC factory, and ready-made presets for more | [Providers](https://docs.theauth.dev/auth/more-providers) |
| Enterprise | Organizations with RBAC, SAML 2.0 and OIDC SSO, SCIM, admin controls, API keys, GDPR export and delete, compliance evidence export (not a certification) | [Docs](https://docs.theauth.dev) |
| CLI | `theauth doctor` checks your setup for common mistakes (`--json` for CI) | [CLI tools](https://docs.theauth.dev/cli-tools) |

The token policy, RFC 9396 rich authorization requests and ID-JAG pieces live in the Go SDK, not here. See [theauth-go](https://github.com/glincker/theauth-go).

17 providers: Apple, Atlassian, Discord, Dropbox, Figma, GitHub, GitLab, Google, LinkedIn, Microsoft, Notion, Reddit, Slack, Spotify, Twitch, Twitter/X, Zoom.

## Frameworks and adapters

Hono, Next.js, SvelteKit, Nuxt, Express, Fastify, Astro, NestJS, SolidStart, TanStack Start, plus clients for React, Vue, Svelte, Expo and Electron. Databases: SQLite, PostgreSQL, MySQL, Cloudflare D1, and Prisma through `@glinr/theauth-prisma`.

<details>
<summary>Next.js (App Router)</summary>

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

// `authenticate` resolves the caller from the request. See the adapter docs.
export const { GET, POST, PATCH, DELETE, OPTIONS } = theAuthNextjs(auth, { authenticate });
```

The adapter serves agent, authorization, delegation and audit routes under `/api/theauth`. Human sign-in is wired separately: see the docs for the methods you enable. Working example: [`examples/nextjs-app`](https://github.com/glincker/theauth/tree/main/examples/nextjs-app).

</details>

<details>
<summary>Hono (Workers, Bun, Node)</summary>

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
app.route("/api/theauth", theAuthHono(auth, { authenticate }));

export default app;
```

Examples: [`hono-server`](https://github.com/glincker/theauth/tree/main/examples/hono-server), [`cloudflare-workers`](https://github.com/glincker/theauth/tree/main/examples/cloudflare-workers).

</details>

Every adapter has the same shape. Per-framework docs: [docs.theauth.dev/adapters](https://docs.theauth.dev/adapters).

## Use cases

### Authentication and authorization for AI agents

Give each agent its own identity, scoped permissions, a delegation chain back to the user who allowed it, budget limits and an audit trail. Start with the [agents guide](https://docs.theauth.dev/agents) and [delegation chains](https://docs.theauth.dev/delegation). To put the policy engine in front of the tools an agent calls, see [guarding agent tools](https://docs.theauth.dev/agent-tools), with walkthroughs for the [Vercel AI SDK](https://docs.theauth.dev/vercel-ai-sdk) ([example](examples/vercel-ai-sdk-guard)) and the [OpenAI Agents SDK](https://docs.theauth.dev/openai-agents-sdk) ([example](examples/openai-agents-guard)).

### OAuth 2.1 authorization server for MCP

Run the authorization side of the Model Context Protocol yourself: PKCE S256, dynamic client registration, resource indicators and protected resource metadata, with optional DPoP-bound tokens. See [MCP OAuth 2.1](https://docs.theauth.dev/mcp) and [DPoP](https://docs.theauth.dev/dpop).

### Sign-in, SSO and provisioning for your product

Email and password, magic links, passkeys, social sign-in, SAML 2.0 and OIDC SSO, SCIM, organizations with roles, and an OpenID Connect provider mode so your other apps can sign in with theAuth. Start with [human auth](https://docs.theauth.dev/auth) and [OIDC provider](https://docs.theauth.dev/auth/oidc-provider).

### Every client surface

Web frameworks, React Native with Expo, Electron, browser extensions and command line tools use the same server. Pick the guide that matches: [adapters](https://docs.theauth.dev/adapters), [Expo](https://docs.theauth.dev/expo), [browser extensions](https://docs.theauth.dev/browser-extension), [CLI sign-in](https://docs.theauth.dev/cli-auth).

## Security and quality

- CodeQL runs on every pull request, and the adapters apply per-client rate limits and cross-site request checks by default.
- About 3,900 test cases across 267 test files cover the core, the adapters and the clients.
- Sessions, passwords and tokens follow the usual hardening: HIBP password checks, DPoP-bound tokens, stateless session cookies bound to the user, one-time codes for native sign-in. Details in [session hardening](https://docs.theauth.dev/session-hardening).
- Responsible disclosure goes to support@glinr.com. See [SECURITY.md](SECURITY.md).

## Migrating from another auth system

Guides with working code for [Auth0](https://docs.theauth.dev/migrate/from-auth0), [Clerk](https://docs.theauth.dev/migrate/from-clerk), [NextAuth and Auth.js](https://docs.theauth.dev/migrate/from-next-auth), [Better Auth](https://docs.theauth.dev/migrate/from-better-auth) and [Kavach](https://docs.theauth.dev/migrate/from-kavach). You can run both systems side by side and move users over lazily: [choose a path](https://docs.theauth.dev/migrate/choose-a-path).

Looking at the differences with specific products? Read the [comparison pages](https://theauth.dev/compare/).

## Packages

All packages live in this monorepo and publish under `@glinr/`. The badge links to the package on npm.

### Core

| Package | npm | What it does |
|---|---|---|
| [`theauth`](packages/core) | [![npm](https://img.shields.io/npm/v/@glinr/theauth?style=flat-square&label=)](https://www.npmjs.com/package/@glinr/theauth) | Open-source auth for AI agents and humans: agent identity, delegation, MCP OAuth 2.1 server, DPoP, passkeys, and audit |
| [`theauth-email`](packages/auth/email) | [![npm](https://img.shields.io/npm/v/@glinr/theauth-email?style=flat-square&label=)](https://www.npmjs.com/package/@glinr/theauth-email) | Email and password authentication for TheAuth |
| [`theauth-mcp`](packages/mcp) | [![npm](https://img.shields.io/npm/v/@glinr/theauth-mcp?style=flat-square&label=)](https://www.npmjs.com/package/@glinr/theauth-mcp) | Read-only MCP server to inspect agent identity, permissions and audit in a theAuth deployment |
| [`theauth-plugin-discovery`](packages/plugins/discovery) | [![npm](https://img.shields.io/npm/v/@glinr/theauth-plugin-discovery?style=flat-square&label=)](https://www.npmjs.com/package/@glinr/theauth-plugin-discovery) | A2A agent capability card discovery plugin for TheAuth |
| [`theauth-plugin-telemetry`](packages/plugins/telemetry) | [![npm](https://img.shields.io/npm/v/@glinr/theauth-plugin-telemetry?style=flat-square&label=)](https://www.npmjs.com/package/@glinr/theauth-plugin-telemetry) | OpenTelemetry integration plugin for TheAuth, converts auth events into OTel spans |

### Clients and UI

| Package | npm | What it does |
|---|---|---|
| [`theauth-client`](packages/client) | [![npm](https://img.shields.io/npm/v/@glinr/theauth-client?style=flat-square&label=)](https://www.npmjs.com/package/@glinr/theauth-client) | TypeScript client for the TheAuth REST API |
| [`theauth-react`](packages/react) | [![npm](https://img.shields.io/npm/v/@glinr/theauth-react?style=flat-square&label=)](https://www.npmjs.com/package/@glinr/theauth-react) | React hooks for TheAuth auth (with v0.5 session rotation) |
| [`theauth-vue`](packages/vue) | [![npm](https://img.shields.io/npm/v/@glinr/theauth-vue?style=flat-square&label=)](https://www.npmjs.com/package/@glinr/theauth-vue) | Vue 3 composables for TheAuth auth |
| [`theauth-svelte`](packages/svelte) | [![npm](https://img.shields.io/npm/v/@glinr/theauth-svelte?style=flat-square&label=)](https://www.npmjs.com/package/@glinr/theauth-svelte) | Svelte stores for TheAuth auth |
| [`theauth-expo`](packages/expo) | [![npm](https://img.shields.io/npm/v/@glinr/theauth-expo?style=flat-square&label=)](https://www.npmjs.com/package/@glinr/theauth-expo) | React Native / Expo client for TheAuth auth |
| [`theauth-electron`](packages/electron) | [![npm](https://img.shields.io/npm/v/@glinr/theauth-electron?style=flat-square&label=)](https://www.npmjs.com/package/@glinr/theauth-electron) | TheAuth auth client for Electron desktop apps |
| [`theauth-extension`](packages/extension) | [![npm](https://img.shields.io/npm/v/@glinr/theauth-extension?style=flat-square&label=)](https://www.npmjs.com/package/@glinr/theauth-extension) | OAuth 2.1 authentication for Manifest V3 browser extensions (PKCE, refresh, optional DPoP) |
| [`theauth-ui`](packages/ui) | [![npm](https://img.shields.io/npm/v/@glinr/theauth-ui?style=flat-square&label=)](https://www.npmjs.com/package/@glinr/theauth-ui) | Pre-built auth UI components for TheAuth |
| [`theauth-ui-headless`](packages/ui-headless) | [![npm](https://img.shields.io/npm/v/@glinr/theauth-ui-headless?style=flat-square&label=)](https://www.npmjs.com/package/@glinr/theauth-ui-headless) | Unstyled, accessible account components for TheAuth: sessions, API and agent tokens, device approval, step-up |
| [`theauth-dashboard`](packages/dashboard) | [![npm](https://img.shields.io/npm/v/@glinr/theauth-dashboard?style=flat-square&label=)](https://www.npmjs.com/package/@glinr/theauth-dashboard) | TheAuth admin dashboard - React UI for managing agents, permissions, and audit logs |

### Framework adapters

| Package | npm | What it does |
|---|---|---|
| [`theauth-astro`](packages/adapters/astro) | [![npm](https://img.shields.io/npm/v/@glinr/theauth-astro?style=flat-square&label=)](https://www.npmjs.com/package/@glinr/theauth-astro) | Astro adapter for TheAuth - exposes agent auth as HTTP REST endpoints |
| [`theauth-express`](packages/adapters/express) | [![npm](https://img.shields.io/npm/v/@glinr/theauth-express?style=flat-square&label=)](https://www.npmjs.com/package/@glinr/theauth-express) | Express adapter for TheAuth - exposes agent auth as HTTP REST endpoints |
| [`theauth-fastify`](packages/adapters/fastify) | [![npm](https://img.shields.io/npm/v/@glinr/theauth-fastify?style=flat-square&label=)](https://www.npmjs.com/package/@glinr/theauth-fastify) | Fastify adapter for TheAuth - exposes agent auth as HTTP REST endpoints |
| [`theauth-hono`](packages/adapters/hono) | [![npm](https://img.shields.io/npm/v/@glinr/theauth-hono?style=flat-square&label=)](https://www.npmjs.com/package/@glinr/theauth-hono) | Hono adapter for TheAuth - exposes agent auth as HTTP REST endpoints |
| [`theauth-nestjs`](packages/adapters/nestjs) | [![npm](https://img.shields.io/npm/v/@glinr/theauth-nestjs?style=flat-square&label=)](https://www.npmjs.com/package/@glinr/theauth-nestjs) | NestJS adapter for TheAuth |
| [`theauth-nextjs`](packages/adapters/nextjs) | [![npm](https://img.shields.io/npm/v/@glinr/theauth-nextjs?style=flat-square&label=)](https://www.npmjs.com/package/@glinr/theauth-nextjs) | Next.js App Router adapter for TheAuth - exposes agent auth as HTTP REST endpoints |
| [`theauth-nextjs-auth`](packages/adapters/nextjs-auth) | [![npm](https://img.shields.io/npm/v/@glinr/theauth-nextjs-auth?style=flat-square&label=)](https://www.npmjs.com/package/@glinr/theauth-nextjs-auth) | Next.js adapter for TheAuth-style external auth backends, cookies, refresh, CSRF, getServerSession, middleware. |
| [`theauth-nuxt`](packages/adapters/nuxt) | [![npm](https://img.shields.io/npm/v/@glinr/theauth-nuxt?style=flat-square&label=)](https://www.npmjs.com/package/@glinr/theauth-nuxt) | Nuxt adapter for TheAuth - exposes agent auth as HTTP REST endpoints via H3 |
| [`theauth-solidstart`](packages/adapters/solidstart) | [![npm](https://img.shields.io/npm/v/@glinr/theauth-solidstart?style=flat-square&label=)](https://www.npmjs.com/package/@glinr/theauth-solidstart) | SolidStart adapter for TheAuth |
| [`theauth-sveltekit`](packages/adapters/sveltekit) | [![npm](https://img.shields.io/npm/v/@glinr/theauth-sveltekit?style=flat-square&label=)](https://www.npmjs.com/package/@glinr/theauth-sveltekit) | SvelteKit adapter for TheAuth - exposes agent auth as HTTP REST endpoints |
| [`theauth-tanstack`](packages/adapters/tanstack) | [![npm](https://img.shields.io/npm/v/@glinr/theauth-tanstack?style=flat-square&label=)](https://www.npmjs.com/package/@glinr/theauth-tanstack) | TanStack Start adapter for TheAuth |

### Database

| Package | npm | What it does |
|---|---|---|
| [`theauth-prisma`](packages/adapters/prisma) | [![npm](https://img.shields.io/npm/v/@glinr/theauth-prisma?style=flat-square&label=)](https://www.npmjs.com/package/@glinr/theauth-prisma) | Prisma database adapter for TheAuth - use PrismaClient as your TheAuth database backend |

### Tooling

| Package | npm | What it does |
|---|---|---|
| [`create-theauth-app`](packages/create-theauth-app) | [![npm](https://img.shields.io/npm/v/@glinr/create-theauth-app?style=flat-square&label=)](https://www.npmjs.com/package/@glinr/create-theauth-app) | Scaffold a TheAuth-powered app in seconds |
| [`theauth-cli`](packages/cli) | [![npm](https://img.shields.io/npm/v/@glinr/theauth-cli?style=flat-square&label=)](https://www.npmjs.com/package/@glinr/theauth-cli) | CLI for theAuth: set up agent identity and MCP OAuth 2.1, run migrations, launch the admin dashboard, codemod from Kavach. |
| [`theauth-gateway`](packages/gateway) | [![npm](https://img.shields.io/npm/v/@glinr/theauth-gateway?style=flat-square&label=)](https://www.npmjs.com/package/@glinr/theauth-gateway) | Standalone auth proxy for TheAuth - enforces auth, authorization, and audit in front of any API or MCP server |
| [`theauth-test-utils`](packages/test-utils) | [![npm](https://img.shields.io/npm/v/@glinr/theauth-test-utils?style=flat-square&label=)](https://www.npmjs.com/package/@glinr/theauth-test-utils) | Test utilities for TheAuth, mock providers, factories, and assertions for auth test suites |

### Other languages

[Go](https://github.com/glincker/theauth-go) ([pkg.go.dev](https://pkg.go.dev/github.com/glincker/theauth-go/v2)), [Python](https://pypi.org/project/theauth/) ([source](sdks/python)) and the [Terraform provider](https://registry.terraform.io/providers/glincker/theauth) ([source](sdks/terraform)).

## Example apps

[`nextjs-app`](examples/nextjs-app), [`nextjs-demo`](examples/nextjs-demo), [`hono-server`](examples/hono-server), [`cloudflare-workers`](examples/cloudflare-workers), [`mcp-server`](examples/mcp-server), [`scim-okta`](examples/scim-okta), [`basic-agent`](examples/basic-agent), [`migrate-from-auth0`](examples/migrate-from-auth0), [`migrate-from-better-auth-agent-plugin`](examples/migrate-from-better-auth-agent-plugin).

## Docs and community

- Docs: [docs.theauth.dev](https://docs.theauth.dev), with [agents](https://docs.theauth.dev/agents), [MCP](https://docs.theauth.dev/mcp), [permissions](https://docs.theauth.dev/permissions) and the [API reference](https://docs.theauth.dev/api).
- Questions and ideas: [GitHub Discussions](https://github.com/glincker/theauth/discussions) or the `#theauth` forum channel in the [GLINR Discord](https://discord.gg/Ar5pcaZB99).
- Hosted option: theAuth Cloud is in early access, see [theauth.dev/pricing](https://theauth.dev/pricing/).
- Changes: [CHANGELOG.md](CHANGELOG.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Issues labeled `good first issue` are a good start. By contributing you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).

## Security

Report vulnerabilities privately to support@glinr.com or through the GitHub advisory form. Do not open a public issue. Details in [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)

## Made by GLINCKER

theAuth is built in the open by [GLINCKER](https://glincker.com), a [GLINR STUDIOS](https://glinr.com) company. Founder: [thegdsks](https://thegdsks.com). Sibling projects: [LevelRail](https://levelrail.com), [theSVG](https://thesvg.org), [GLINUI](https://glinui.com).
