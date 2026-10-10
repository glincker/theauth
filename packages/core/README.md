[npm](https://www.npmjs.com/package/@glinr/theauth) · [Source](https://github.com/glincker/theauth/tree/main/packages/core) · [Docs](https://docs.theauth.dev/concepts) · [All packages](https://github.com/glincker/theauth#packages)

<p align="center">
  <img src="https://theauth.dev/logo.svg" height="64" alt="theAuth" />
</p>

<h1 align="center">theauth</h1>

<p align="center">
  <strong>The auth OS for AI agents and humans</strong><br />
  Identity, permissions, delegation, and audit for the agentic era.
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/@glinr/theauth"><img src="https://img.shields.io/npm/v/@glinr/theauth?style=flat-square&color=c9a84c" alt="npm" /></a>
  <a href="https://www.npmjs.com/package/@glinr/theauth"><img src="https://img.shields.io/npm/dm/@glinr/theauth?style=flat-square&color=c9a84c" alt="downloads" /></a>
  <a href="https://github.com/glincker/theauth/actions"><img src="https://img.shields.io/github/actions/workflow/status/glincker/theauth/ci.yml?style=flat-square&label=tests" alt="tests" /></a>
  <a href="https://github.com/glincker/theauth/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" alt="MIT" /></a>
  <a href="https://www.typescriptlang.org/"><img src="https://img.shields.io/badge/TypeScript-strict-blue?style=flat-square" alt="TypeScript" /></a>
  <a href="https://docs.theauth.dev"><img src="https://img.shields.io/badge/docs-theauth.dev-c9a84c?style=flat-square" alt="docs" /></a>
</p>

<p align="center">
  <a href="https://theauth.dev">Website</a> &middot;
  <a href="https://docs.theauth.dev/quickstart">Quickstart</a> &middot;
  <a href="https://docs.theauth.dev">Documentation</a> &middot;
  <a href="https://github.com/glincker/theauth/tree/main/examples">Examples</a> &middot;
  <a href="https://theauth.dev/pricing/">Cloud (early access)</a>
</p>

Part of [theAuth](https://theauth.dev), open-source auth for AI agents and humans. Docs: [docs.theauth.dev](https://docs.theauth.dev).

---

## Why theauth?

Every auth library handles human login. None of them handle **AI agent identity**. theAuth gives every agent its own bearer token, scoped permissions, delegation chains, and an immutable audit trail. Plus full human auth (14 methods, 17 OAuth providers, passkeys, SSO) so you don't need two auth systems.

```
npm install @glinr/theauth
```

## Quick start

```typescript
import { createTheAuth, users } from "@glinr/theauth";

const theauth = await createTheAuth({
  database: { provider: "sqlite", url: ":memory:" },
  agents: { enabled: true }, // creates the agent and audit tables
});

// An agent needs an owner row in theauth_users (human auth creates these for you).
theauth.db.insert(users).values({
  id: "user-123", email: "owner@example.com", name: "Owner",
  createdAt: new Date(), updatedAt: new Date(),
}).run();

// Create an AI agent with scoped permissions
const agent = await theauth.agent.create({
  ownerId: "user-123",
  name: "github-reader",
  type: "autonomous",
  permissions: [
    { resource: "mcp:github:*", actions: ["read"] },
    { resource: "mcp:deploy:production", actions: ["execute"],
      constraints: { requireApproval: true } },
  ],
});

// Authorize and audit
const result = await theauth.authorize(agent.id, {
  action: "read",
  resource: "mcp:github:repos",
});
// { allowed: true, auditId: "aud_..." }
```

## Features

<table>
<tr>
<td width="50%">

### Agent identity
- Cryptographic bearer tokens (`kv_...`)
- Wildcard permission matching (`mcp:github:*`)
- Delegation chains with depth limits
- Immutable audit trail
- Trust scoring
- Budget policies and cost attribution
- CIBA-style human approval flows

</td>
<td width="50%">

### Human auth (14 methods)
- Email + password
- Magic link, email OTP
- Passkey / WebAuthn
- TOTP 2FA
- Phone SMS
- Google One-tap
- Sign In With Ethereum
- Anonymous auth
- Session freshness enforcement

</td>
</tr>
<tr>
<td>

### OAuth (17 providers)
Apple, Atlassian, Discord, Dropbox, Figma, GitHub, GitLab, Google, LinkedIn, Microsoft, Notion, Reddit, Slack, Spotify, Twitch, Twitter/X, Zoom, plus a generic OIDC factory for anything else.

</td>
<td>

### MCP OAuth 2.1
Spec-compliant authorization server for Model Context Protocol. PKCE S256, RFC 9728 / 8707 / 8414 / 7591.

</td>
</tr>
<tr>
<td>

### Enterprise
Organizations + RBAC, SAML SSO, SCIM directory sync, admin controls, API key management, multi-tenant isolation, GDPR compliance.

</td>
<td>

### Edge compatible
Runs on Cloudflare Workers (D1), Deno, Bun, and Node.js. Only 4 runtime deps: `drizzle-orm`, `jose`, `sql.js`, `zod`.

</td>
</tr>
</table>

### Security

Rate limiting (per-agent and per-IP) &middot; HIBP breach checking &middot; CSRF protection &middot; httpOnly secure cookies &middot; Email enumeration prevention &middot; Trusted device windows &middot; Password reset with signed tokens

## SCIM 2.0 compatibility

Full RFC 7644 protocol and RFC 7643 core schema, with a working demo against Okta. See [`examples/scim-okta`](../../examples/scim-okta) and the [SCIM guide](https://docs.theauth.dev/auth/scim).

| Area | Status | Notes |
|---|---|---|
| Discovery (`/ServiceProviderConfig`, `/Schemas`, `/ResourceTypes`) | ✓ | Enterprise User extension advertised in `/Schemas` |
| `/Users` CRUD | ✓ | POST, GET, PUT, PATCH, DELETE |
| `/Groups` CRUD | ✓ | Backed by `theauth_organizations` + `theauth_org_members` |
| `/Me` | ✓ | Opt-in via `resolveSelf` callback |
| `/Bulk` | 501 | Deliberate, advertised as `supported: false` |
| Filter grammar (§3.4.2.2) | ✓ | eq, ne, co, sw, ew, gt, ge, lt, le, pr, and, or, not, parens, value-path |
| PATCH path expressions (§3.5.2) | ✓ | Includes `emails[type eq "work"].value`, op cap of 1000, immutable checks |
| Sort (§3.4.2.3) | ✓ | `sortBy` + `sortOrder` with `id` tie-break |
| Pagination | ✓ | `startIndex`, `count`, `totalResults` |
| Enterprise User extension (RFC 7643 §4.3) | ✓ | `employeeNumber`, `department`, `manager`, etc. |
| Audit log on every write | ✓ | `auditLogs` row per POST/PUT/PATCH/DELETE |
| Bearer token auth | ✓ | Only supported scheme |
| ETag / conditional requests | No | Not implemented |
| Groups PATCH with value-filter member ops | Partial | Routes through legacy handler |

Tested against Okta's SCIM test suite categories: discovery, Users CRUD, Groups CRUD, filter (all listed ops), PATCH simple paths, PATCH value-paths, Enterprise User, pagination, sort. Outstanding gaps are the two rows above.

## Framework adapters

Works with every major framework:

| Framework | Package | Framework | Package |
|-----------|---------|-----------|---------|
| **Hono** | `@glinr/theauth-hono` | **Nuxt** | `@glinr/theauth-nuxt` |
| **Express** | `@glinr/theauth-express` | **SvelteKit** | `@glinr/theauth-sveltekit` |
| **Next.js** | `@glinr/theauth-nextjs` | **Astro** | `@glinr/theauth-astro` |
| **Fastify** | `@glinr/theauth-fastify` | **NestJS** | `@glinr/theauth-nestjs` |

## Client libraries

| Package | What |
|---------|------|
| `@glinr/theauth-react` | TheAuthProvider + hooks |
| `@glinr/theauth-vue` | Vue 3 plugin + composables |
| `@glinr/theauth-svelte` | Svelte stores |
| `@glinr/theauth-ui` | 7 pre-built auth components (SignIn, SignUp, UserButton...) |
| `@glinr/theauth-expo` | React Native / Expo |
| `@glinr/theauth-electron` | Electron desktop |
| `@glinr/theauth-client` | Zero-dep TypeScript REST client |

## Databases

SQLite, PostgreSQL, MySQL, Cloudflare D1, libSQL (Turso). Tables are auto-created on first run.

```typescript
// Cloudflare Workers + D1
createTheAuth({ database: { provider: "d1", binding: env.THEAUTH_DB } });

// PostgreSQL
createTheAuth({ database: { provider: "postgres", url: process.env.DATABASE_URL } });
```

On D1, the tables are created in one batch the first time an isolate builds the instance. If you would rather run `wrangler d1 migrations apply`, set `skipMigrations: true` and write the SQL to a migration file with `getMigrationStatements`:

```typescript
import { getMigrationStatements } from "@glinr/theauth";

const sql = getMigrationStatements("d1", { agents: { enabled: true } })
  .map((statement) => `${statement};`)
  .join("\n\n");
```

## Plugins

Auth methods are plugins. Enable what you need:

```typescript
import {
  emailPassword, magicLink, passkey, totp,
  organizations, sso, admin, apiKeys, webhooks,
} from "@glinr/theauth/auth";

createTheAuth({
  database: { provider: "sqlite", url: "theauth.db" },
  plugins: [emailPassword(), magicLink({ sendMagicLink }), passkey(), totp()],
});
```

## theAuth Cloud

Don't want to self-host? [theAuth Cloud](https://theauth.dev/pricing/) (early access) is the managed version with dashboard, billing, and zero infrastructure.

| | Free | Starter | Growth | Scale |
|---|---|---|---|---|
| MAU | 1,000 | 10,000 | 50,000 | 200,000 |
| Price | $0 | $29/mo | $79/mo | $199/mo |

[Cloud early access](https://theauth.dev/pricing/) &middot; [Compare plans](https://theauth.dev/pricing/) &middot; [Self-host instead](https://docs.theauth.dev/quickstart)

## Documentation

Full docs at **[docs.theauth.dev](https://docs.theauth.dev)**

## Community

[![Discord](https://img.shields.io/discord/829168897080557579?style=flat-square&logo=discord&logoColor=white&label=discord&color=5865F2)](https://discord.gg/Ar5pcaZB99)

Questions and help in the `#theauth` forum on the [GLINR Discord](https://discord.gg/Ar5pcaZB99).

## License

[MIT](https://github.com/glincker/theauth/blob/main/LICENSE)
