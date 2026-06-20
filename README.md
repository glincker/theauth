<p align="center">
  <img src="https://theauth.com/logo.svg" height="64" alt="TheAuth" />
</p>

<h1 align="center">TheAuth</h1>

<p align="center">
  Auth for AI agents and humans. One library, both sides.
</p>

<p align="center">
  by <a href="https://glincker.com"><strong>GLINR STUDIOS</strong></a> · a <a href="https://glincker.com">GLINCKER LLC</a> project
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/theauth"><img src="https://img.shields.io/npm/v/theauth?style=flat&colorA=000000&colorB=000000&label=npm" alt="npm version" /></a>
  <a href="https://www.npmjs.com/package/theauth"><img src="https://img.shields.io/npm/dm/theauth?style=flat&colorA=000000&colorB=000000&label=downloads" alt="monthly downloads" /></a>
  <a href="https://github.com/glincker/theauth/stargazers"><img src="https://img.shields.io/github/stars/glincker/theauth?style=flat&colorA=000000&colorB=000000&label=stars" alt="GitHub stars" /></a>
</p>

<p align="center">
  <a href="https://docs.theauth.com/docs/quickstart">Quickstart</a> ·
  <a href="https://docs.theauth.com/docs">Documentation</a> ·
  <a href="https://github.com/glincker/theauth/tree/main/examples">Examples</a> ·
  <a href="https://github.com/glincker/theauth/discussions">Discussions</a> ·
  <a href="https://app.theauth.com">TheAuth Cloud</a>
</p>

<p align="center">
  <a href="https://theauth.com">
    <img src="https://theauth.com/theauth-og-img.png" alt="TheAuth, auth OS for AI agents and humans" width="960" />
  </a>
</p>

---

## Why TheAuth

Most auth libraries stop at human sign-in. That leaves you stitching together separate systems when your AI agents need identity, scoped permissions, delegation, and audit trails. TheAuth handles both in one place.

### How it differs

Ask yourself about the auth library you're using or evaluating:

- Does it model AI agents as first-class identities, with their own scoped permissions and an audit trail you can export, not just human users with API keys?
- Does it ship an MCP OAuth 2.1 authorization server that complies with the published RFC stack (9728, 8707, 8414, 7591), so your agents can talk to MCP servers without you writing the spec?
- Does it run on Cloudflare Workers, Bun, and Deno without Node-only APIs in the core?
- Does it give you delegation chains with depth limits, budget policies per agent, and CIBA-style approval flows for sensitive tool calls?

If any of those is a no, that gap is why theauth exists.

### Agent identity

Cryptographic bearer tokens (`kv_...`), wildcard permission matching, delegation chains with depth limits, budget policies, anomaly detection, and CIBA approval flows.

### Human auth

14 methods: email/password, magic link, email OTP, phone SMS, passkey/WebAuthn, TOTP 2FA, anonymous, Google One-tap, Sign In With Ethereum, device authorization, username/password, captcha, password reset, session freshness.

### OAuth

17 first-class providers: Apple, Atlassian, Discord, Dropbox, Figma, GitHub, GitLab, Google, LinkedIn, Microsoft, Notion, Reddit, Slack, Spotify, Twitch, Twitter/X, Zoom. Plus a generic OIDC factory for anything else.

### MCP OAuth 2.1

Authorization server for the Model Context Protocol. PKCE S256, RFC 9728 / 8707 / 8414 / 7591.

### Enterprise

Organizations with RBAC, SAML 2.0 and OIDC SSO, admin controls (ban/impersonate), API key management, SCIM directory sync, multi-tenant isolation, GDPR export/delete/anonymize, compliance reports for EU AI Act, NIST, SOC 2, ISO 42001.

### Runs on the edge

Works on Cloudflare Workers, Deno, and Bun without code changes. Three runtime dependencies: `drizzle-orm`, `jose`, `zod`.

### Security

Rate limiting per agent and per IP, HIBP password breach checking, CSRF protection, httpOnly secure cookies, email enumeration prevention, trusted device windows, signed expiring reset tokens, session freshness enforcement.

### Performance

The policy engine hits 2.6M warm-cache evals/sec with a p99 of 500ns. Cold paths stay under 0.3ms p99 on direct permissions, RBAC role expansion, and ReBAC graph lookups. Numbers from `pnpm bench` on the `policy-engine` suite in `packages/core/bench/`, reproducible locally.

---

## Install

```bash
npm install theauth
```

## Quick start

```typescript
import { createKavach } from "theauth";
import { emailPassword } from "theauth/auth";
import { createHonoAdapter } from "@theauth/hono";

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
import { createKavach } from "theauth";
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

## Packages

### Core

| Package | What it does | |
| --- | --- | --- |
| [`theauth`](https://www.npmjs.com/package/theauth) | Core SDK: agents, permissions, delegation, audit, auth plugins | [![npm](https://img.shields.io/npm/v/theauth?style=flat-square&color=c9a84c)](https://www.npmjs.com/package/theauth) |
| [`@theauth/client`](https://www.npmjs.com/package/@theauth/client) | TypeScript REST client, no dependencies | [![npm](https://img.shields.io/npm/v/@theauth/client?style=flat-square)](https://www.npmjs.com/package/@theauth/client) |
| [`@theauth/cli`](https://www.npmjs.com/package/@theauth/cli) | `kavach init`, `kavach migrate`, `kavach dashboard` | [![npm](https://img.shields.io/npm/v/@theauth/cli?style=flat-square)](https://www.npmjs.com/package/@theauth/cli) |
| [`@theauth/dashboard`](https://www.npmjs.com/package/@theauth/dashboard) | Embeddable React admin UI | [![npm](https://img.shields.io/npm/v/@theauth/dashboard?style=flat-square)](https://www.npmjs.com/package/@theauth/dashboard) |
| [`@theauth/gateway`](https://www.npmjs.com/package/@theauth/gateway) | Auth proxy with rate limiting | [![npm](https://img.shields.io/npm/v/@theauth/gateway?style=flat-square)](https://www.npmjs.com/package/@theauth/gateway) |

### Client libraries

| Package | What it does | |
| --- | --- | --- |
| [`@theauth/react`](https://www.npmjs.com/package/@theauth/react) | `KavachProvider` + hooks | [![npm](https://img.shields.io/npm/v/@theauth/react?style=flat-square)](https://www.npmjs.com/package/@theauth/react) |
| [`@theauth/vue`](https://www.npmjs.com/package/@theauth/vue) | Vue 3 plugin + composables | [![npm](https://img.shields.io/npm/v/@theauth/vue?style=flat-square)](https://www.npmjs.com/package/@theauth/vue) |
| [`@theauth/svelte`](https://www.npmjs.com/package/@theauth/svelte) | Svelte stores | [![npm](https://img.shields.io/npm/v/@theauth/svelte?style=flat-square)](https://www.npmjs.com/package/@theauth/svelte) |
| [`@theauth/ui`](https://www.npmjs.com/package/@theauth/ui) | Sign-in, sign-up, user button components | [![npm](https://img.shields.io/npm/v/@theauth/ui?style=flat-square)](https://www.npmjs.com/package/@theauth/ui) |
| [`@theauth/expo`](https://www.npmjs.com/package/@theauth/expo) | React Native / Expo with SecureStore | [![npm](https://img.shields.io/npm/v/@theauth/expo?style=flat-square)](https://www.npmjs.com/package/@theauth/expo) |
| [`@theauth/electron`](https://www.npmjs.com/package/@theauth/electron) | Electron with safeStorage + OAuth popup | [![npm](https://img.shields.io/npm/v/@theauth/electron?style=flat-square)](https://www.npmjs.com/package/@theauth/electron) |
| [`@theauth/test-utils`](https://www.npmjs.com/package/@theauth/test-utils) | Mocks, factories, test assertions | [![npm](https://img.shields.io/npm/v/@theauth/test-utils?style=flat-square)](https://www.npmjs.com/package/@theauth/test-utils) |

### Framework adapters

| Package | Framework | |
| --- | --- | --- |
| [`@theauth/hono`](https://www.npmjs.com/package/@theauth/hono) | Hono | [![npm](https://img.shields.io/npm/v/@theauth/hono?style=flat-square)](https://www.npmjs.com/package/@theauth/hono) |
| [`@theauth/express`](https://www.npmjs.com/package/@theauth/express) | Express | [![npm](https://img.shields.io/npm/v/@theauth/express?style=flat-square)](https://www.npmjs.com/package/@theauth/express) |
| [`@theauth/nextjs`](https://www.npmjs.com/package/@theauth/nextjs) | Next.js (App Router) — bundles the agent-management runtime | [![npm](https://img.shields.io/npm/v/@theauth/nextjs?style=flat-square)](https://www.npmjs.com/package/@theauth/nextjs) |
| [`@theauth/nextjs-auth`](https://www.npmjs.com/package/@theauth/nextjs-auth) | Next.js adapter for external auth backends — getServerSession, withAuth middleware, cookie + CSRF + token rotation | [![npm](https://img.shields.io/npm/v/@theauth/nextjs-auth?style=flat-square)](https://www.npmjs.com/package/@theauth/nextjs-auth) |
| [`@theauth/fastify`](https://www.npmjs.com/package/@theauth/fastify) | Fastify | [![npm](https://img.shields.io/npm/v/@theauth/fastify?style=flat-square)](https://www.npmjs.com/package/@theauth/fastify) |
| [`@theauth/nuxt`](https://www.npmjs.com/package/@theauth/nuxt) | Nuxt | [![npm](https://img.shields.io/npm/v/@theauth/nuxt?style=flat-square)](https://www.npmjs.com/package/@theauth/nuxt) |
| [`@theauth/sveltekit`](https://www.npmjs.com/package/@theauth/sveltekit) | SvelteKit | [![npm](https://img.shields.io/npm/v/@theauth/sveltekit?style=flat-square)](https://www.npmjs.com/package/@theauth/sveltekit) |
| [`@theauth/astro`](https://www.npmjs.com/package/@theauth/astro) | Astro | [![npm](https://img.shields.io/npm/v/@theauth/astro?style=flat-square)](https://www.npmjs.com/package/@theauth/astro) |
| [`@theauth/nestjs`](https://www.npmjs.com/package/@theauth/nestjs) | NestJS | [![npm](https://img.shields.io/npm/v/@theauth/nestjs?style=flat-square)](https://www.npmjs.com/package/@theauth/nestjs) |
| [`@theauth/solidstart`](https://www.npmjs.com/package/@theauth/solidstart) | SolidStart | [![npm](https://img.shields.io/npm/v/@theauth/solidstart?style=flat-square)](https://www.npmjs.com/package/@theauth/solidstart) |
| [`@theauth/tanstack`](https://www.npmjs.com/package/@theauth/tanstack) | TanStack Start | [![npm](https://img.shields.io/npm/v/@theauth/tanstack?style=flat-square)](https://www.npmjs.com/package/@theauth/tanstack) |

### Database adapters

Core ships with SQLite, Postgres, MySQL, and Cloudflare D1 providers built in. Use the Prisma adapter when your app already owns a PrismaClient and you want TheAuth to share the same connection.

| Package | What it does | |
| --- | --- | --- |
| [`@theauth/prisma`](https://www.npmjs.com/package/@theauth/prisma) | Prisma adapter, pass a PrismaClient as the TheAuth database | [![npm](https://img.shields.io/npm/v/@theauth/prisma?style=flat-square)](https://www.npmjs.com/package/@theauth/prisma) |

---

## UI components

If you want ready-made forms, `@theauth/ui` has them. Override styling with `classNames`, swap sub-components, or skip the package entirely and use hooks from `@theauth/react`.

```tsx
import { SignIn, OAUTH_PROVIDERS } from "@theauth/ui";

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

Everything is a plugin. Auth methods, security features, integrations. Turn on what you need:

```typescript
import { createKavach } from "theauth";
import {
  emailPassword,
  magicLink,
  passkey,
  totp,
  organizations,
  sso,
  admin,
  apiKeys,
  jwtSession,
} from "theauth/auth";

const kavach = createKavach({
  database: { provider: "postgres", url: process.env.DATABASE_URL },
  plugins: [
    emailPassword({
      passwordReset: {
        sendResetEmail: async (email, url) => {
          /* your email sender */
        },
      },
    }),
    magicLink({
      sendMagicLink: async (email, url) => {
        /* your email sender */
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

## Docs

[docs.theauth.com](https://docs.theauth.com/docs)

- [Getting started](https://docs.theauth.com/docs/quickstart)
- [Authentication](https://docs.theauth.com/docs/auth)
- [Agent identity](https://docs.theauth.com/docs/agents)
- [Permissions and delegation](https://docs.theauth.com/docs/permissions)
- [MCP OAuth 2.1](https://docs.theauth.com/docs/mcp)
- [Framework adapters](https://docs.theauth.com/docs/adapters)
- [API reference](https://docs.theauth.com/docs/api)

---

## TheAuth Cloud

TheAuth Cloud is the hosted version. Dashboard, billing, no infrastructure.

|       | Free  | Starter | Growth | Scale   | Enterprise |
| ----- | ----- | ------- | ------ | ------- | ---------- |
| MAU   | 1,000 | 10,000  | 50,000 | 200,000 | Custom     |
| Price | $0    | $29/mo  | $79/mo | $199/mo | Custom     |

All plans include MCP OAuth 2.1, agent identity, delegation, trust scoring, and compliance reports.

<p align="center">
  <a href="https://app.theauth.com/sign-up"><strong>Start free</strong></a> ·
  <a href="https://theauth.com/pricing">Pricing</a> ·
  <a href="https://docs.theauth.com/docs/quickstart">Self-host instead</a>
</p>

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

<a href="https://github.com/glincker/theauth/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=glincker/theauth" alt="Contributors to the TheAuth repository" />
</a>

## Support

- [SUPPORT.md](SUPPORT.md) for help
- [SECURITY.md](SECURITY.md) to report vulnerabilities
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)

## License

[MIT](LICENSE)

---

<p align="center">A <a href="https://glincker.com">GLINCKER LLC</a> open source project</p>

---

> **Rebranded from `kavachos` in June 2026.** If you're arriving from the old `kavachos` / `@kavachos/*` npm packages, the API surface is unchanged — only the package names and import paths have moved. See [MIGRATION.md](docs/migrate/index.mdx) or just swap `@kavachos/` → `@theauth/` in your imports.
