<p align="center">
  <img src="https://theauth.dev/logo.svg" height="64" alt="TheAuth" />
</p>

<h1 align="center">TheAuth</h1>

<p align="center">
  Auth for AI agents and humans. One library, both sides.
</p>

<p align="center">
  by <a href="https://glincker.com"><strong>GLINR STUDIOS</strong></a> · a <a href="https://glincker.com">GLINCKER LLC</a> project
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/@glinr/theauth"><img src="https://img.shields.io/npm/v/@glinr/theauth?style=flat&colorA=000000&colorB=000000&label=npm" alt="npm version" /></a>
  <a href="https://www.npmjs.com/package/@glinr/theauth"><img src="https://img.shields.io/npm/dm/@glinr/theauth?style=flat&colorA=000000&colorB=000000&label=downloads" alt="monthly downloads" /></a>
  <a href="https://github.com/glincker/theauth/stargazers"><img src="https://img.shields.io/github/stars/glincker/theauth?style=flat&colorA=000000&colorB=000000&label=stars" alt="GitHub stars" /></a>
</p>

<p align="center">
  <a href="https://docs.theauth.dev/docs/quickstart">Quickstart</a> ·
  <a href="https://docs.theauth.dev/docs">Documentation</a> ·
  <a href="https://github.com/glincker/theauth/tree/main/examples">Examples</a> ·
  <a href="https://github.com/glincker/theauth/discussions">Discussions</a> ·
  <a href="https://app.theauth.dev">TheAuth Cloud</a>
</p>

<p align="center">
  <a href="https://theauth.dev">
    <img src="https://theauth.dev/theauth-og-img.png" alt="TheAuth, auth OS for AI agents and humans" width="960" />
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
npm install @glinr/theauth
```

## Quick start

```typescript
import { createKavach } from "@glinr/theauth";
import { emailPassword } from "@glinr/theauth/auth";
import { createHonoAdapter } from "@glinr/theauth-hono";

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
import { createKavach } from "@glinr/theauth";
import { Hono } from "hono";

type Env = { THEAUTH_DB: D1Database };
const app = new Hono<{ Bindings: Env }>();

app.get("/health", async (c) => {
  const kavach = await createKavach({
    database: { provider: "d1", binding: c.env.THEAUTH_DB },
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
| [`@glinr/theauth`](https://www.npmjs.com/package/@glinr/theauth) | Core SDK: agents, permissions, delegation, audit, auth plugins | [![npm](https://img.shields.io/npm/v/@glinr/theauth?style=flat-square&color=c9a84c)](https://www.npmjs.com/package/@glinr/theauth) |
| [`@glinr/theauth-client`](https://www.npmjs.com/package/@glinr/theauth-client) | TypeScript REST client, no dependencies | [![npm](https://img.shields.io/npm/v/@glinr/theauth-client?style=flat-square)](https://www.npmjs.com/package/@glinr/theauth-client) |
| [`@glinr/theauth-cli`](https://www.npmjs.com/package/@glinr/theauth-cli) | `kavach init`, `kavach migrate`, `kavach dashboard` | [![npm](https://img.shields.io/npm/v/@glinr/theauth-cli?style=flat-square)](https://www.npmjs.com/package/@glinr/theauth-cli) |
| [`@glinr/theauth-dashboard`](https://www.npmjs.com/package/@glinr/theauth-dashboard) | Embeddable React admin UI | [![npm](https://img.shields.io/npm/v/@glinr/theauth-dashboard?style=flat-square)](https://www.npmjs.com/package/@glinr/theauth-dashboard) |
| [`@glinr/theauth-gateway`](https://www.npmjs.com/package/@glinr/theauth-gateway) | Auth proxy with rate limiting | [![npm](https://img.shields.io/npm/v/@glinr/theauth-gateway?style=flat-square)](https://www.npmjs.com/package/@glinr/theauth-gateway) |

### Client libraries

| Package | What it does | |
| --- | --- | --- |
| [`@glinr/theauth-react`](https://www.npmjs.com/package/@glinr/theauth-react) | `KavachProvider` + hooks | [![npm](https://img.shields.io/npm/v/@glinr/theauth-react?style=flat-square)](https://www.npmjs.com/package/@glinr/theauth-react) |
| [`@glinr/theauth-vue`](https://www.npmjs.com/package/@glinr/theauth-vue) | Vue 3 plugin + composables | [![npm](https://img.shields.io/npm/v/@glinr/theauth-vue?style=flat-square)](https://www.npmjs.com/package/@glinr/theauth-vue) |
| [`@glinr/theauth-svelte`](https://www.npmjs.com/package/@glinr/theauth-svelte) | Svelte stores | [![npm](https://img.shields.io/npm/v/@glinr/theauth-svelte?style=flat-square)](https://www.npmjs.com/package/@glinr/theauth-svelte) |
| [`@glinr/theauth-ui`](https://www.npmjs.com/package/@glinr/theauth-ui) | Sign-in, sign-up, user button components | [![npm](https://img.shields.io/npm/v/@glinr/theauth-ui?style=flat-square)](https://www.npmjs.com/package/@glinr/theauth-ui) |
| [`@glinr/theauth-expo`](https://www.npmjs.com/package/@glinr/theauth-expo) | React Native / Expo with SecureStore | [![npm](https://img.shields.io/npm/v/@glinr/theauth-expo?style=flat-square)](https://www.npmjs.com/package/@glinr/theauth-expo) |
| [`@glinr/theauth-electron`](https://www.npmjs.com/package/@glinr/theauth-electron) | Electron with safeStorage + OAuth popup | [![npm](https://img.shields.io/npm/v/@glinr/theauth-electron?style=flat-square)](https://www.npmjs.com/package/@glinr/theauth-electron) |
| [`@glinr/theauth-test-utils`](https://www.npmjs.com/package/@glinr/theauth-test-utils) | Mocks, factories, test assertions | [![npm](https://img.shields.io/npm/v/@glinr/theauth-test-utils?style=flat-square)](https://www.npmjs.com/package/@glinr/theauth-test-utils) |

### Framework adapters

| Package | Framework | |
| --- | --- | --- |
| [`@glinr/theauth-hono`](https://www.npmjs.com/package/@glinr/theauth-hono) | Hono | [![npm](https://img.shields.io/npm/v/@glinr/theauth-hono?style=flat-square)](https://www.npmjs.com/package/@glinr/theauth-hono) |
| [`@glinr/theauth-express`](https://www.npmjs.com/package/@glinr/theauth-express) | Express | [![npm](https://img.shields.io/npm/v/@glinr/theauth-express?style=flat-square)](https://www.npmjs.com/package/@glinr/theauth-express) |
| [`@glinr/theauth-nextjs`](https://www.npmjs.com/package/@glinr/theauth-nextjs) | Next.js (App Router) — bundles the agent-management runtime | [![npm](https://img.shields.io/npm/v/@glinr/theauth-nextjs?style=flat-square)](https://www.npmjs.com/package/@glinr/theauth-nextjs) |
| [`@glinr/theauth-nextjs-auth`](https://www.npmjs.com/package/@glinr/theauth-nextjs-auth) | Next.js adapter for external auth backends — getServerSession, withAuth middleware, cookie + CSRF + token rotation | [![npm](https://img.shields.io/npm/v/@glinr/theauth-nextjs-auth?style=flat-square)](https://www.npmjs.com/package/@glinr/theauth-nextjs-auth) |
| [`@glinr/theauth-fastify`](https://www.npmjs.com/package/@glinr/theauth-fastify) | Fastify | [![npm](https://img.shields.io/npm/v/@glinr/theauth-fastify?style=flat-square)](https://www.npmjs.com/package/@glinr/theauth-fastify) |
| [`@glinr/theauth-nuxt`](https://www.npmjs.com/package/@glinr/theauth-nuxt) | Nuxt | [![npm](https://img.shields.io/npm/v/@glinr/theauth-nuxt?style=flat-square)](https://www.npmjs.com/package/@glinr/theauth-nuxt) |
| [`@glinr/theauth-sveltekit`](https://www.npmjs.com/package/@glinr/theauth-sveltekit) | SvelteKit | [![npm](https://img.shields.io/npm/v/@glinr/theauth-sveltekit?style=flat-square)](https://www.npmjs.com/package/@glinr/theauth-sveltekit) |
| [`@glinr/theauth-astro`](https://www.npmjs.com/package/@glinr/theauth-astro) | Astro | [![npm](https://img.shields.io/npm/v/@glinr/theauth-astro?style=flat-square)](https://www.npmjs.com/package/@glinr/theauth-astro) |
| [`@glinr/theauth-nestjs`](https://www.npmjs.com/package/@glinr/theauth-nestjs) | NestJS | [![npm](https://img.shields.io/npm/v/@glinr/theauth-nestjs?style=flat-square)](https://www.npmjs.com/package/@glinr/theauth-nestjs) |
| [`@glinr/theauth-solidstart`](https://www.npmjs.com/package/@glinr/theauth-solidstart) | SolidStart | [![npm](https://img.shields.io/npm/v/@glinr/theauth-solidstart?style=flat-square)](https://www.npmjs.com/package/@glinr/theauth-solidstart) |
| [`@glinr/theauth-tanstack`](https://www.npmjs.com/package/@glinr/theauth-tanstack) | TanStack Start | [![npm](https://img.shields.io/npm/v/@glinr/theauth-tanstack?style=flat-square)](https://www.npmjs.com/package/@glinr/theauth-tanstack) |

### Database adapters

Core ships with SQLite, Postgres, MySQL, and Cloudflare D1 providers built in. Use the Prisma adapter when your app already owns a PrismaClient and you want TheAuth to share the same connection.

| Package | What it does | |
| --- | --- | --- |
| [`@glinr/theauth-prisma`](https://www.npmjs.com/package/@glinr/theauth-prisma) | Prisma adapter, pass a PrismaClient as the TheAuth database | [![npm](https://img.shields.io/npm/v/@glinr/theauth-prisma?style=flat-square)](https://www.npmjs.com/package/@glinr/theauth-prisma) |

---

## UI components

If you want ready-made forms, `@glinr/theauth-ui` has them. Override styling with `classNames`, swap sub-components, or skip the package entirely and use hooks from `@glinr/theauth-react`.

```tsx
import { SignIn, OAUTH_PROVIDERS } from "@glinr/theauth-ui";

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
import { createKavach } from "@glinr/theauth";
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
} from "@glinr/theauth/auth";

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

[docs.theauth.dev](https://docs.theauth.dev/docs)

- [Getting started](https://docs.theauth.dev/docs/quickstart)
- [Authentication](https://docs.theauth.dev/docs/auth)
- [Agent identity](https://docs.theauth.dev/docs/agents)
- [Permissions and delegation](https://docs.theauth.dev/docs/permissions)
- [MCP OAuth 2.1](https://docs.theauth.dev/docs/mcp)
- [Framework adapters](https://docs.theauth.dev/docs/adapters)
- [API reference](https://docs.theauth.dev/docs/api)

---

## TheAuth Cloud

TheAuth Cloud is the hosted version. Dashboard, billing, no infrastructure.

|       | Free  | Starter | Growth | Scale   | Enterprise |
| ----- | ----- | ------- | ------ | ------- | ---------- |
| MAU   | 1,000 | 10,000  | 50,000 | 200,000 | Custom     |
| Price | $0    | $29/mo  | $79/mo | $199/mo | Custom     |

All plans include MCP OAuth 2.1, agent identity, delegation, trust scoring, and compliance reports.

<p align="center">
  <a href="https://app.theauth.dev/sign-up"><strong>Start free</strong></a> ·
  <a href="https://theauth.dev/pricing">Pricing</a> ·
  <a href="https://docs.theauth.dev/docs/quickstart">Self-host instead</a>
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

> **Rebranded from `kavachos` in June 2026, then moved to the `@glinr/` npm scope shortly after.** If you're arriving from the old `kavachos` / `@kavachos/*` packages, swap `@kavachos/` for `@glinr/theauth-` in your imports. If you're coming from a brief `@theauth/*` window, swap `@theauth/` for `@glinr/theauth-`. The API surface is unchanged. See [MIGRATION.md](docs/migrate/index.mdx).
