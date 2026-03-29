<p align="center">
  <img src="https://kavachos.com/logo.svg" height="80" alt="KavachOS" />
</p>

<h1 align="center">KavachOS</h1>

<p align="center">
  <strong>The auth OS for AI agents and humans</strong><br />
  Identity, permissions, delegation, and audit for the agentic era.<br />
  Full human auth (email, OAuth, passkeys, SSO) plus agent-first primitives that nothing else ships.
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/kavachos"><img src="https://img.shields.io/npm/v/kavachos?style=flat-square&color=c9a84c&label=npm" alt="npm" /></a>
  <a href="https://www.npmjs.com/package/kavachos"><img src="https://img.shields.io/npm/dm/kavachos?style=flat-square&color=c9a84c&label=downloads" alt="downloads" /></a>
  <a href="https://github.com/kavachos/kavachos/actions"><img src="https://img.shields.io/github/actions/workflow/status/kavachos/kavachos/ci.yml?style=flat-square&label=CI" alt="CI" /></a>
  <a href="https://github.com/kavachos/kavachos/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" alt="MIT" /></a>
  <a href="https://www.typescriptlang.org/"><img src="https://img.shields.io/badge/TypeScript-strict-blue?style=flat-square" alt="TypeScript" /></a>
  <a href="https://docs.kavachos.com"><img src="https://img.shields.io/badge/docs-kavachos.com-c9a84c?style=flat-square" alt="docs" /></a>
  <a href="https://discord.gg/kavachos"><img src="https://img.shields.io/badge/Discord-join-5865F2?style=flat-square&logo=discord&logoColor=white" alt="Discord" /></a>
</p>

<p align="center">
  <a href="https://docs.kavachos.com/docs/quickstart">Quickstart</a> &middot;
  <a href="https://docs.kavachos.com/docs">Documentation</a> &middot;
  <a href="https://github.com/kavachos/kavachos/tree/main/examples">Examples</a> &middot;
  <a href="https://app.kavachos.com">KavachOS Cloud</a> &middot;
  <a href="https://discord.gg/kavachos">Discord</a>
</p>

---

## Install

```bash
npm install kavachos
```

## Quickstart

```typescript
import { createKavach } from "kavachos";
import { emailPassword } from "kavachos/auth";
import { createHonoAdapter } from "@kavachos/hono";

const kavach = createKavach({
  database: { provider: "sqlite", url: "kavach.db" },
  plugins: [emailPassword()],
});

// Mount on any framework
const app = new Hono();
app.route("/api/kavach", createHonoAdapter(kavach));

// Create an AI agent with scoped permissions
const agent = await kavach.agent.create({
  ownerId: "user-123",
  name: "github-reader",
  type: "autonomous",
  permissions: [
    { resource: "mcp:github:*", actions: ["read"] },
    {
      resource: "mcp:deploy:production",
      actions: ["execute"],
      constraints: { requireApproval: true },
    },
  ],
});

// Authorize and audit (< 1ms)
const result = await kavach.authorize(agent.id, {
  action: "read",
  resource: "mcp:github:repos",
});
// { allowed: true, auditId: "aud_..." }
```

<details>
<summary><strong>Cloudflare Workers + D1 example</strong></summary>

```typescript
import { createKavach } from "kavachos";
import { Hono } from "hono";

type Env = { KAVACH_DB: D1Database };
const app = new Hono<{ Bindings: Env }>();

app.get("/health", async (c) => {
  const kavach = await createKavach({
    database: { provider: "d1", binding: c.env.KAVACH_DB },
  });

  const agent = await kavach.agent.create({
    ownerId: "user-1",
    name: "my-agent",
    type: "autonomous",
    permissions: [{ resource: "mcp:github:*", actions: ["read"] }],
  });

  return c.json({ agent });
});

export default app;
```

</details>

---

## What makes KavachOS different

<table>
<tr>
<td width="50%" valign="top">

### 🤖 Agent identity

Cryptographic bearer tokens (`kv_...`), wildcard permission matching, delegation chains with depth limits, immutable audit trail, trust scoring, anomaly detection, budget policies, CIBA approval flows.

**No other auth library ships this.**

</td>
<td width="50%" valign="top">

### 👤 Human auth (14 methods)

Email + password, magic link, email OTP, phone SMS, passkey/WebAuthn, TOTP 2FA, anonymous, Google One-tap, Sign In With Ethereum, device authorization, username + password, captcha, password reset, session freshness.

</td>
</tr>
<tr>
<td valign="top">

### 🔗 OAuth (27+ providers)

Google, GitHub, Apple, Microsoft, Discord, Slack, GitLab, LinkedIn, Twitter/X, Facebook, Spotify, Twitch, Reddit, Notion, plus a generic OIDC factory that adds any provider in 10 lines.

</td>
<td valign="top">

### 🔐 MCP OAuth 2.1

Spec-compliant authorization server for the Model Context Protocol. PKCE S256, RFC 9728 / 8707 / 8414 / 7591. The only OSS implementation.

</td>
</tr>
<tr>
<td valign="top">

### 🏢 Enterprise

Organizations + RBAC, SAML 2.0 + OIDC SSO, admin (ban/impersonate), API key management, SCIM directory sync, multi-tenant isolation, GDPR (export/delete/anonymize), compliance reports (EU AI Act, NIST, SOC 2, ISO 42001).

</td>
<td valign="top">

### ⚡ Edge compatible

Runs on Cloudflare Workers, Deno, and Bun with no code changes. Use D1 as the database. Only 3 runtime deps: `drizzle-orm`, `jose`, `zod`.

</td>
</tr>
</table>

### 🛡️ Security

Rate limiting (per-agent and per-IP) &middot; HIBP password breach checking &middot; CSRF protection &middot; httpOnly secure cookies &middot; Email enumeration prevention &middot; Trusted device windows &middot; Password reset with signed, expiring tokens &middot; Session freshness enforcement

---

## Packages

### Core

| Package                                                                    | What                                                           |                                                                                                                                 |
| -------------------------------------------------------------------------- | -------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| [`kavachos`](https://www.npmjs.com/package/kavachos)                       | Core SDK: agents, permissions, delegation, audit, auth plugins | [![npm](https://img.shields.io/npm/v/kavachos?style=flat-square&color=c9a84c)](https://www.npmjs.com/package/kavachos)          |
| [`@kavachos/client`](https://www.npmjs.com/package/@kavachos/client)       | Zero-dep TypeScript REST client                                | [![npm](https://img.shields.io/npm/v/@kavachos/client?style=flat-square)](https://www.npmjs.com/package/@kavachos/client)       |
| [`@kavachos/cli`](https://www.npmjs.com/package/@kavachos/cli)             | CLI: init, migrate, dashboard                                  | [![npm](https://img.shields.io/npm/v/@kavachos/cli?style=flat-square)](https://www.npmjs.com/package/@kavachos/cli)             |
| [`@kavachos/dashboard`](https://www.npmjs.com/package/@kavachos/dashboard) | Embeddable React admin dashboard (9 pages)                     | [![npm](https://img.shields.io/npm/v/@kavachos/dashboard?style=flat-square)](https://www.npmjs.com/package/@kavachos/dashboard) |
| [`@kavachos/gateway`](https://www.npmjs.com/package/@kavachos/gateway)     | Standalone auth proxy with rate limiting                       | [![npm](https://img.shields.io/npm/v/@kavachos/gateway?style=flat-square)](https://www.npmjs.com/package/@kavachos/gateway)     |

### Client libraries

| Package                                                                      | What                                       |                                                                                                                                   |
| ---------------------------------------------------------------------------- | ------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------- |
| [`@kavachos/react`](https://www.npmjs.com/package/@kavachos/react)           | KavachProvider + hooks                     | [![npm](https://img.shields.io/npm/v/@kavachos/react?style=flat-square)](https://www.npmjs.com/package/@kavachos/react)           |
| [`@kavachos/vue`](https://www.npmjs.com/package/@kavachos/vue)               | Vue 3 plugin + composables                 | [![npm](https://img.shields.io/npm/v/@kavachos/vue?style=flat-square)](https://www.npmjs.com/package/@kavachos/vue)               |
| [`@kavachos/svelte`](https://www.npmjs.com/package/@kavachos/svelte)         | Svelte stores                              | [![npm](https://img.shields.io/npm/v/@kavachos/svelte?style=flat-square)](https://www.npmjs.com/package/@kavachos/svelte)         |
| [`@kavachos/ui`](https://www.npmjs.com/package/@kavachos/ui)                 | 7 pre-built auth components                | [![npm](https://img.shields.io/npm/v/@kavachos/ui?style=flat-square)](https://www.npmjs.com/package/@kavachos/ui)                 |
| [`@kavachos/expo`](https://www.npmjs.com/package/@kavachos/expo)             | React Native / Expo with SecureStore       | [![npm](https://img.shields.io/npm/v/@kavachos/expo?style=flat-square)](https://www.npmjs.com/package/@kavachos/expo)             |
| [`@kavachos/electron`](https://www.npmjs.com/package/@kavachos/electron)     | Electron desktop: safeStorage, OAuth popup | [![npm](https://img.shields.io/npm/v/@kavachos/electron?style=flat-square)](https://www.npmjs.com/package/@kavachos/electron)     |
| [`@kavachos/test-utils`](https://www.npmjs.com/package/@kavachos/test-utils) | Mock providers, factories, assertions      | [![npm](https://img.shields.io/npm/v/@kavachos/test-utils?style=flat-square)](https://www.npmjs.com/package/@kavachos/test-utils) |

### Framework adapters

| Package                                                                      | Framework            |                                                                                                                                   |
| ---------------------------------------------------------------------------- | -------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| [`@kavachos/hono`](https://www.npmjs.com/package/@kavachos/hono)             | Hono                 | [![npm](https://img.shields.io/npm/v/@kavachos/hono?style=flat-square)](https://www.npmjs.com/package/@kavachos/hono)             |
| [`@kavachos/express`](https://www.npmjs.com/package/@kavachos/express)       | Express              | [![npm](https://img.shields.io/npm/v/@kavachos/express?style=flat-square)](https://www.npmjs.com/package/@kavachos/express)       |
| [`@kavachos/nextjs`](https://www.npmjs.com/package/@kavachos/nextjs)         | Next.js (App Router) | [![npm](https://img.shields.io/npm/v/@kavachos/nextjs?style=flat-square)](https://www.npmjs.com/package/@kavachos/nextjs)         |
| [`@kavachos/fastify`](https://www.npmjs.com/package/@kavachos/fastify)       | Fastify              | [![npm](https://img.shields.io/npm/v/@kavachos/fastify?style=flat-square)](https://www.npmjs.com/package/@kavachos/fastify)       |
| [`@kavachos/nuxt`](https://www.npmjs.com/package/@kavachos/nuxt)             | Nuxt                 | [![npm](https://img.shields.io/npm/v/@kavachos/nuxt?style=flat-square)](https://www.npmjs.com/package/@kavachos/nuxt)             |
| [`@kavachos/sveltekit`](https://www.npmjs.com/package/@kavachos/sveltekit)   | SvelteKit            | [![npm](https://img.shields.io/npm/v/@kavachos/sveltekit?style=flat-square)](https://www.npmjs.com/package/@kavachos/sveltekit)   |
| [`@kavachos/astro`](https://www.npmjs.com/package/@kavachos/astro)           | Astro                | [![npm](https://img.shields.io/npm/v/@kavachos/astro?style=flat-square)](https://www.npmjs.com/package/@kavachos/astro)           |
| [`@kavachos/nestjs`](https://www.npmjs.com/package/@kavachos/nestjs)         | NestJS               | [![npm](https://img.shields.io/npm/v/@kavachos/nestjs?style=flat-square)](https://www.npmjs.com/package/@kavachos/nestjs)         |
| [`@kavachos/solidstart`](https://www.npmjs.com/package/@kavachos/solidstart) | SolidStart           | [![npm](https://img.shields.io/npm/v/@kavachos/solidstart?style=flat-square)](https://www.npmjs.com/package/@kavachos/solidstart) |
| [`@kavachos/tanstack`](https://www.npmjs.com/package/@kavachos/tanstack)     | TanStack Start       | [![npm](https://img.shields.io/npm/v/@kavachos/tanstack?style=flat-square)](https://www.npmjs.com/package/@kavachos/tanstack)     |

---

## UI components

Drop-in auth forms. Override styling with `classNames`, replace sub-components, or skip the package and use hooks from `@kavachos/react`.

```tsx
import { SignIn, OAUTH_PROVIDERS } from "@kavachos/ui";

<SignIn
  providers={[OAUTH_PROVIDERS.google, OAUTH_PROVIDERS.github]}
  showMagicLink
  signUpUrl="/sign-up"
  forgotPasswordUrl="/forgot-password"
  onSuccess={() => router.push("/dashboard")}
/>;
```

---

## Plugins

Auth methods, security features, and integrations are all plugins. Enable what you need:

```typescript
import { createKavach } from "kavachos";
import {
  emailPassword,
  magicLink,
  passkey,
  totp,
  organizations,
  sso,
  admin,
  apiKeys,
  captcha,
  gdpr,
  webhooks,
  scim,
  jwtSession,
  openApi,
  stripe,
} from "kavachos/auth";

const kavach = createKavach({
  database: { provider: "postgres", url: process.env.DATABASE_URL },
  plugins: [
    emailPassword({
      passwordReset: {
        sendResetEmail: async (email, url) => {
          /* your sender */
        },
      },
    }),
    magicLink({
      sendMagicLink: async (email, url) => {
        /* your sender */
      },
    }),
    passkey(),
    totp(),
    organizations(),
    sso(),
    admin(),
    apiKeys(),
    jwtSession({ secret: process.env.JWT_SECRET }),
  ],
});
```

---

## Documentation

Full docs at **[docs.kavachos.com](https://docs.kavachos.com/docs)**

- [Getting started](https://docs.kavachos.com/docs/quickstart)
- [Authentication](https://docs.kavachos.com/docs/auth)
- [Agent identity](https://docs.kavachos.com/docs/agents)
- [Permissions](https://docs.kavachos.com/docs/permissions)
- [Delegation](https://docs.kavachos.com/docs/delegation)
- [MCP OAuth 2.1](https://docs.kavachos.com/docs/mcp)
- [Framework adapters](https://docs.kavachos.com/docs/adapters)
- [REST API reference](https://docs.kavachos.com/docs/api)

---

## KavachOS Cloud

Managed hosting with a dashboard, billing, and zero infrastructure to manage.

|       | Free  | Starter | Growth | Scale   | Enterprise |
| ----- | ----- | ------- | ------ | ------- | ---------- |
| MAU   | 1,000 | 10,000  | 50,000 | 200,000 | Custom     |
| Price | $0    | $29/mo  | $79/mo | $199/mo | Custom     |

Every plan includes MCP OAuth 2.1, agent identity, delegation chains, trust scoring, and compliance reports.

<p align="center">
  <a href="https://app.kavachos.com/sign-up"><strong>Start free</strong></a> &middot;
  <a href="https://kavachos.com/pricing">Pricing</a> &middot;
  <a href="https://docs.kavachos.com/docs/quickstart">Self-host instead</a>
</p>

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Community and support

- Support channels: [SUPPORT.md](SUPPORT.md)
- Security reporting: [SECURITY.md](SECURITY.md)
- Community standards: [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
- Maintainer workflow: [MAINTAINERS.md](MAINTAINERS.md)
- Project governance: [GOVERNANCE.md](GOVERNANCE.md)

## License

MIT
