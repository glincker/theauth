<p align="center">
<pre>
████████╗██╗  ██╗███████╗ █████╗ ██╗   ██╗████████╗██╗  ██╗
╚══██╔══╝██║  ██║██╔════╝██╔══██╗██║   ██║╚══██╔══╝██║  ██║
   ██║   ███████║█████╗  ███████║██║   ██║   ██║   ███████║
   ██║   ██╔══██║██╔══╝  ██╔══██║██║   ██║   ██║   ██╔══██║
   ██║   ██║  ██║███████╗██║  ██║╚██████╔╝   ██║   ██║  ██║
   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝
</pre>
</p>

<h2 align="center"><em>Type-safe authentication for TypeScript. OAuth 2.1, MCP, passkeys, agents.</em></h2>

<p align="center">
  by <a href="https://glincker.com"><strong>GLINR STUDIOS</strong></a> &middot; a <a href="https://glincker.com">GLINCKER LLC</a> project
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/@glinr/theauth"><img src="https://img.shields.io/npm/v/@glinr/theauth?style=flat&colorA=000000&colorB=000000&label=npm" alt="npm version" /></a>
  <a href="https://www.npmjs.com/package/@glinr/theauth"><img src="https://img.shields.io/npm/dm/@glinr/theauth?style=flat&colorA=000000&colorB=000000&label=downloads" alt="monthly downloads" /></a>
  <a href="https://github.com/glincker/theauth/blob/main/LICENSE"><img src="https://img.shields.io/github/license/glincker/theauth?style=flat&colorA=000000&colorB=000000&label=license" alt="License" /></a>
  <a href="https://github.com/glincker/theauth/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/glincker/theauth/ci.yml?branch=main&style=flat&colorA=000000&colorB=000000&label=CI" alt="CI status" /></a>
  <a href="https://bundlephobia.com/package/@glinr/theauth"><img src="https://img.shields.io/bundlephobia/minzip/@glinr/theauth?style=flat&colorA=000000&colorB=000000&label=bundle" alt="bundle size" /></a>
  <a href="https://www.typescriptlang.org/"><img src="https://img.shields.io/badge/TypeScript-strict-blue?style=flat&colorA=000000&colorB=3178c6&logo=typescript&logoColor=white" alt="TypeScript strict" /></a>
  <a href="https://github.com/glincker/theauth/discussions"><img src="https://img.shields.io/github/discussions/glincker/theauth?style=flat&colorA=000000&colorB=000000&label=discussions" alt="GitHub Discussions" /></a>
</p>

<p align="center">
  <a href="https://docs.theauth.com/docs/quickstart"><strong>Quickstart</strong></a> &middot;
  <a href="https://docs.theauth.com/docs"><strong>Docs</strong></a> &middot;
  <a href="https://github.com/glincker/theauth/tree/main/examples"><strong>Examples</strong></a> &middot;
  <a href="https://github.com/glincker/theauth/discussions"><strong>Discussions</strong></a> &middot;
  <a href="https://app.theauth.com"><strong>TheAuth Cloud</strong></a>
</p>

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
import { createKavach } from "@glinr/theauth";
import { emailPassword, passkey } from "@glinr/theauth/auth";
import { createHonoAdapter } from "@glinr/theauth-hono";

const kavach = createKavach({
  database: { provider: "postgres", url: process.env.DATABASE_URL },
  plugins: [emailPassword(), passkey()],
});

const app = new Hono();
app.route("/api/auth", createHonoAdapter(kavach));

// Create an AI agent with scoped MCP permissions
const agent = await kavach.agent.create({
  ownerId: "user-123",
  name: "github-reader",
  type: "autonomous",
  permissions: [{ resource: "mcp:github:*", actions: ["read"] }],
});

const result = await kavach.authorize(agent.id, {
  action: "read",
  resource: "mcp:github:repos",
});
// { allowed: true, auditId: "aud_..." }
```

---

## Why theauth

Most auth libraries stop at human sign-in. That leaves you stitching together separate systems when your AI agents need identity, scoped permissions, delegation, and audit trails. theauth handles both in one place.

| Capability | Auth0 | Clerk | Better-Auth | NextAuth | Lucia | **theauth** |
|---|---|---|---|---|---|---|
| License | Proprietary | Proprietary | MIT | ISC | MIT | **MIT** |
| Self-hosted | Partial | No | Yes | Yes | Yes | **Yes** |
| OAuth 2.1 server | Yes | Yes | Partial | No | No | **Yes** |
| MCP OAuth 2.1 | No | No | No | No | No | **Yes** |
| Passkeys / WebAuthn | Yes | Yes | Plugin | Plugin | No | **Yes** |
| Multi-tenant / orgs | Yes | Yes | Plugin | No | No | **Yes** |
| Audit log | Yes (paid) | Yes (paid) | No | No | No | **Yes** |
| AI agent identity | No | No | No | No | No | **Yes** |
| Edge runtimes | Partial | No | Yes | Partial | Yes | **Yes** |

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
- Anomaly detection
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
- Compliance reports: EU AI Act, NIST, SOC 2, ISO 42001

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
// app/api/auth/[...theauth]/route.ts
import { createKavach } from "@glinr/theauth";
import { emailPassword } from "@glinr/theauth/auth";
import { createNextAuthHandler } from "@glinr/theauth-nextjs";

const kavach = createKavach({
  database: { provider: "postgres", url: process.env.DATABASE_URL },
  plugins: [emailPassword()],
});

const handler = createNextAuthHandler(kavach);
export { handler as GET, handler as POST };
```

```typescript
// app/dashboard/page.tsx (Server Component)
import { getServerSession } from "@glinr/theauth-nextjs";

export default async function Dashboard() {
  const session = await getServerSession();
  if (!session) redirect("/sign-in");
  return <h1>Hello, {session.user.email}</h1>;
}
```

See [`examples/nextjs-app`](https://github.com/glincker/theauth/tree/main/examples/nextjs-app) for a full working example.

</details>

<details>
<summary><strong>SvelteKit</strong></summary>

```bash
npm install @glinr/theauth @glinr/theauth-sveltekit
```

```typescript
// src/hooks.server.ts
import { createKavach } from "@glinr/theauth";
import { emailPassword } from "@glinr/theauth/auth";
import { createSvelteKitHandler } from "@glinr/theauth-sveltekit";

const kavach = createKavach({
  database: { provider: "sqlite", url: "kavach.db" },
  plugins: [emailPassword()],
});

export const handle = createSvelteKitHandler(kavach);
```

```typescript
// src/routes/+layout.server.ts
import { getSession } from "@glinr/theauth-sveltekit";

export async function load(event) {
  const session = await getSession(event);
  return { session };
}
```

</details>

<details>
<summary><strong>Vue / Nuxt</strong></summary>

```bash
npm install @glinr/theauth @glinr/theauth-nuxt
```

```typescript
// server/plugins/theauth.ts
import { createKavach } from "@glinr/theauth";
import { emailPassword } from "@glinr/theauth/auth";

export const kavach = createKavach({
  database: { provider: "postgres", url: process.env.DATABASE_URL },
  plugins: [emailPassword()],
});
```

```typescript
// nuxt.config.ts
export default defineNuxtConfig({
  modules: ["@glinr/theauth-nuxt"],
});
```

</details>

<details>
<summary><strong>Hono (Cloudflare Workers / Express / Bun)</strong></summary>

```bash
npm install @glinr/theauth @glinr/theauth-hono
```

```typescript
import { Hono } from "hono";
import { createKavach } from "@glinr/theauth";
import { emailPassword } from "@glinr/theauth/auth";
import { createHonoAdapter } from "@glinr/theauth-hono";

type Env = { DATABASE_URL: string };
const app = new Hono<{ Bindings: Env }>();

app.use("/api/auth/*", async (c, next) => {
  const kavach = createKavach({
    database: { provider: "postgres", url: c.env.DATABASE_URL },
    plugins: [emailPassword()],
  });
  return createHonoAdapter(kavach)(c, next);
});

export default app;
```

See [`examples/hono-server`](https://github.com/glincker/theauth/tree/main/examples/hono-server) and [`examples/cloudflare-workers`](https://github.com/glincker/theauth/tree/main/examples/cloudflare-workers).

</details>

---

## Documentation

**Primary docs:** [docs.theauth.com](https://docs.theauth.com/docs)

| Section | Link | What you will find |
|---|---|---|
| Getting Started | [docs.theauth.com/docs/quickstart](https://docs.theauth.com/docs/quickstart) | Installation, first auth flow |
| Authentication | [docs.theauth.com/docs/auth](https://docs.theauth.com/docs/auth) | All auth methods and plugins |
| Agent Identity | [docs.theauth.com/docs/agents](https://docs.theauth.com/docs/agents) | Agent tokens, delegation, policies |
| Permissions | [docs.theauth.com/docs/permissions](https://docs.theauth.com/docs/permissions) | RBAC, wildcard matching, ReBAC |
| MCP OAuth 2.1 | [docs.theauth.com/docs/mcp](https://docs.theauth.com/docs/mcp) | MCP auth server setup |
| Framework Adapters | [docs.theauth.com/docs/adapters](https://docs.theauth.com/docs/adapters) | Next.js, Hono, SvelteKit, etc. |
| API Reference | [docs.theauth.com/docs/api](https://docs.theauth.com/docs/api) | Config, types, errors |
| Security | [SECURITY.md](SECURITY.md) | Threat model, disclosure policy |

---

## Framework adapters

| Package | Framework | Directory |
|---|---|---|
| `@glinr/theauth-nextjs` | Next.js 15 (App Router) | [`packages/adapters/nextjs`](https://github.com/glincker/theauth/tree/main/packages/adapters/nextjs) |
| `@glinr/theauth-nextjs-auth` | Next.js (external auth backend) | [`packages/adapters/nextjs-auth`](https://github.com/glincker/theauth/tree/main/packages/adapters/nextjs-auth) |
| `@glinr/theauth-hono` | Hono (Workers, Bun, Deno) | [`packages/adapters/hono`](https://github.com/glincker/theauth/tree/main/packages/adapters/hono) |
| `@glinr/theauth-express` | Express | [`packages/adapters/express`](https://github.com/glincker/theauth/tree/main/packages/adapters/express) |
| `@glinr/theauth-fastify` | Fastify | [`packages/adapters/fastify`](https://github.com/glincker/theauth/tree/main/packages/adapters/fastify) |
| `@glinr/theauth-sveltekit` | SvelteKit | [`packages/adapters/sveltekit`](https://github.com/glincker/theauth/tree/main/packages/adapters/sveltekit) |
| `@glinr/theauth-nuxt` | Nuxt / Vue 3 | [`packages/adapters/nuxt`](https://github.com/glincker/theauth/tree/main/packages/adapters/nuxt) |
| `@glinr/theauth-astro` | Astro | [`packages/adapters/astro`](https://github.com/glincker/theauth/tree/main/packages/adapters/astro) |
| `@glinr/theauth-nestjs` | NestJS | [`packages/adapters/nestjs`](https://github.com/glincker/theauth/tree/main/packages/adapters/nestjs) |
| `@glinr/theauth-solidstart` | SolidStart | [`packages/adapters/solidstart`](https://github.com/glincker/theauth/tree/main/packages/adapters/solidstart) |
| `@glinr/theauth-tanstack` | TanStack Start | [`packages/adapters/tanstack`](https://github.com/glincker/theauth/tree/main/packages/adapters/tanstack) |
| `@glinr/theauth-expo` | React Native / Expo | [`packages/adapters/expo`](https://github.com/glincker/theauth/tree/main/packages/adapters/expo) |
| `@glinr/theauth-electron` | Electron | [`packages/adapters/electron`](https://github.com/glincker/theauth/tree/main/packages/adapters/electron) |

---

## Database adapters

SQLite, PostgreSQL, MySQL, and Cloudflare D1 are built into the core package. Use the Prisma adapter to share an existing PrismaClient.

| Package | What it connects | Directory |
|---|---|---|
| Built-in SQLite | `better-sqlite3`, `bun:sqlite`, D1 | core |
| Built-in PostgreSQL | `pg`, `postgres`, Neon, Supabase | core |
| Built-in MySQL | `mysql2` | core |
| `@glinr/theauth-prisma` | Prisma (share your PrismaClient) | [`packages/prisma`](https://github.com/glincker/theauth/tree/main/packages/prisma) |

---

## Example apps

| Example | What it shows | Directory |
|---|---|---|
| `nextjs-app` | Full Next.js 15 App Router integration | [`examples/nextjs-app`](https://github.com/glincker/theauth/tree/main/examples/nextjs-app) |
| `nextjs-demo` | UI components + sign-in flows | [`examples/nextjs-demo`](https://github.com/glincker/theauth/tree/main/examples/nextjs-demo) |
| `hono-server` | Standalone Hono API with auth | [`examples/hono-server`](https://github.com/glincker/theauth/tree/main/examples/hono-server) |
| `cloudflare-workers` | Workers + D1 database | [`examples/cloudflare-workers`](https://github.com/glincker/theauth/tree/main/examples/cloudflare-workers) |
| `mcp-server` | MCP OAuth 2.1 authorization server | [`examples/mcp-server`](https://github.com/glincker/theauth/tree/main/examples/mcp-server) |
| `basic-agent` | AI agent token issuance and policy | [`examples/basic-agent`](https://github.com/glincker/theauth/tree/main/examples/basic-agent) |
| `migrate-from-auth0` | Step-by-step Auth0 migration | [`examples/migrate-from-auth0`](https://github.com/glincker/theauth/tree/main/examples/migrate-from-auth0) |
| `migrate-from-better-auth-agent-plugin` | Migration from better-auth agent plugin | [`examples/migrate-from-better-auth-agent-plugin`](https://github.com/glincker/theauth/tree/main/examples/migrate-from-better-auth-agent-plugin) |

---

## TheAuth Cloud

Hosted version with dashboard, billing, and zero infrastructure. [app.theauth.com](https://app.theauth.com)

| Plan | MAU | Price |
|---|---|---|
| Free | 1,000 | $0 |
| Starter | 10,000 | $29/mo |
| Growth | 50,000 | $79/mo |
| Scale | 200,000 | $199/mo |
| Enterprise | Custom | Custom |

---

## Security

Responsible disclosure: see [SECURITY.md](SECURITY.md). Do not open a public issue for vulnerabilities.

---

## Roadmap

Follow development on [GitHub Discussions](https://github.com/glincker/theauth/discussions) and the [changelog](CHANGELOG.md).

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). First-time contributor? Look for issues labeled `good first issue`.

By contributing, you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).

---

## License

[MIT](LICENSE) (c) GLINCKER LLC

---

<p align="center">
  <em>Built by the founder of <a href="https://thesvg.org">theSVG.org</a>.</em>
  <br />
  <em>A Product of <strong>GLINR STUDIOS</strong> | <strong>A GLINCKER COMPANY</strong></em>
</p>
