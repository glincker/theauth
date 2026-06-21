<p align="center">
  <img src="https://theauth.com/logo.svg" height="64" alt="TheAuth" />
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
  <a href="https://docs.theauth.com"><img src="https://img.shields.io/badge/docs-theauth.com-c9a84c?style=flat-square" alt="docs" /></a>
</p>

<p align="center">
  <a href="https://docs.theauth.com/docs/quickstart">Quickstart</a> &middot;
  <a href="https://docs.theauth.com/docs">Documentation</a> &middot;
  <a href="https://github.com/glincker/theauth/tree/main/examples">Examples</a> &middot;
  <a href="https://app.theauth.com">TheAuth Cloud</a>
</p>

---

## Why theauth?

Every auth library handles human login. None of them handle **AI agent identity**. TheAuth gives every agent its own bearer token, scoped permissions, delegation chains, and an immutable audit trail. Plus full human auth (14 methods, 17 OAuth providers, passkeys, SSO) so you don't need two auth systems.

```
npm install @glinr/theauth
```

## Quick start

```typescript
import { createKavach } from "@glinr/theauth";
import { emailPassword } from "@glinr/theauth/auth";

const kavach = createKavach({
  database: { provider: "sqlite", url: "kavach.db" },
  plugins: [emailPassword()],
});

// Create an AI agent with scoped permissions
const agent = await kavach.agent.create({
  ownerId: "user-123",
  name: "github-reader",
  type: "autonomous",
  permissions: [
    { resource: "mcp:github:*", actions: ["read"] },
    { resource: "mcp:deploy:production", actions: ["execute"],
      constraints: { requireApproval: true } },
  ],
});

// Authorize and audit (< 1ms)
const result = await kavach.authorize(agent.id, {
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
- Trust scoring and anomaly detection
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
Runs on Cloudflare Workers (D1), Deno, Bun, and Node.js. Only 3 runtime deps: `drizzle-orm`, `jose`, `zod`.

</td>
</tr>
</table>

### Security

Rate limiting (per-agent and per-IP) &middot; HIBP breach checking &middot; CSRF protection &middot; httpOnly secure cookies &middot; Email enumeration prevention &middot; Trusted device windows &middot; Password reset with signed tokens

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
| `@glinr/theauth-react` | KavachProvider + hooks |
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
createKavach({ database: { provider: "d1", binding: env.KAVACH_DB } });

// PostgreSQL
createKavach({ database: { provider: "postgres", url: process.env.DATABASE_URL } });
```

## Plugins

Auth methods are plugins. Enable what you need:

```typescript
import {
  emailPassword, magicLink, passkey, totp,
  organizations, sso, admin, apiKeys, webhooks,
} from "@glinr/theauth/auth";

createKavach({
  database: { provider: "sqlite", url: "kavach.db" },
  plugins: [emailPassword(), magicLink({ sendMagicLink }), passkey(), totp()],
});
```

## TheAuth Cloud

Don't want to self-host? [TheAuth Cloud](https://app.theauth.com) is the managed version with dashboard, billing, and zero infrastructure.

| | Free | Starter | Growth | Scale |
|---|---|---|---|---|
| MAU | 1,000 | 10,000 | 50,000 | 200,000 |
| Price | $0 | $29/mo | $79/mo | $199/mo |

[Start free](https://app.theauth.com/sign-up) &middot; [Compare plans](https://theauth.com/pricing) &middot; [Self-host instead](https://docs.theauth.com/docs/quickstart)

## Documentation

Full docs at **[docs.theauth.com](https://docs.theauth.com/docs)**

## License

[MIT](https://github.com/glincker/theauth/blob/main/LICENSE)
