<p align="center">
  <img src="https://theauth.dev/logo.svg" height="64" alt="theAuth" />
</p>

<h1 align="center">theAuth</h1>

<p align="center"><strong>Open-source auth for AI agents and humans.</strong><br>
Agent identity, delegation, MCP OAuth 2.1 server, DPoP, passkeys, device flow. A self-hostable Better Auth alternative for TypeScript.</p>

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

## 30 second quickstart

Runs as pasted with SQLite. Needs Node 20 or newer.

```bash
npm install @glinr/theauth
```

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

## How theAuth compares

Checked against each vendor's public docs on 2026-10-07. Vendors change fast, so verify against their docs. Write-ups with sources: [theauth.dev/compare](https://theauth.dev/compare/).

| Capability | Auth0 | Clerk | Better Auth | **theAuth** |
|---|---|---|---|---|
| Source license | Proprietary | Proprietary | MIT | **MIT** |
| Self-hostable | Managed private cloud only | No | Yes | **Yes** |
| OAuth 2.1 server for MCP | Yes | Yes | Yes | **Yes** |
| Agent identity as its own model | Add-on: Token Vault, CIBA | Not found in docs | Plugin, not yet stable | **Yes, core** |
| Enterprise SSO | Yes | Yes | Plugin | **SAML 2.0, OIDC, SCIM** |

Where theAuth is the weaker choice: Better Auth has a larger community, more tutorials and a bigger plugin catalog. Auth0 and Clerk are managed products with hosted UIs and support contracts, which we do not match. Pick theAuth when agents are first-class users of your system and you want to run the whole thing yourself. Migration guides: [`migrate-from-auth0`](https://github.com/glincker/theauth/tree/main/examples/migrate-from-auth0), [`migrate-from-better-auth-agent-plugin`](https://github.com/glincker/theauth/tree/main/examples/migrate-from-better-auth-agent-plugin).

## Packages

All packages live in this monorepo and publish under `@glinr/`.

| Group | Packages |
|---|---|
| Core | [`theauth`](packages/core), [`theauth-email`](packages/auth/email), [`theauth-plugin-discovery`](packages/plugins/discovery), [`theauth-plugin-telemetry`](packages/plugins/telemetry) |
| Clients and UI | [`theauth-client`](packages/client), [`theauth-react`](packages/react), [`theauth-vue`](packages/vue), [`theauth-svelte`](packages/svelte), [`theauth-expo`](packages/expo), [`theauth-electron`](packages/electron), [`theauth-ui`](packages/ui), [`theauth-ui-headless`](packages/ui-headless), [`theauth-dashboard`](packages/dashboard) |
| Framework adapters | [`theauth-hono`](packages/adapters/hono), [`theauth-nextjs`](packages/adapters/nextjs), [`theauth-nextjs-auth`](packages/adapters/nextjs-auth), [`theauth-sveltekit`](packages/adapters/sveltekit), [`theauth-nuxt`](packages/adapters/nuxt), [`theauth-express`](packages/adapters/express), [`theauth-fastify`](packages/adapters/fastify), [`theauth-astro`](packages/adapters/astro), [`theauth-nestjs`](packages/adapters/nestjs), [`theauth-solidstart`](packages/adapters/solidstart), [`theauth-tanstack`](packages/adapters/tanstack) |
| Database | [`theauth-prisma`](packages/adapters/prisma) |
| Tooling | [`create-theauth-app`](packages/create-theauth-app), [`theauth-cli`](packages/cli), [`theauth-gateway`](packages/gateway), [`theauth-test-utils`](packages/test-utils) |
| Other languages | [Go](https://github.com/glincker/theauth-go) ([pkg.go.dev](https://pkg.go.dev/github.com/glincker/theauth-go/v2)), [Python](https://pypi.org/project/theauth/) ([source](sdks/python)), [Terraform provider](https://registry.terraform.io/providers/glincker/theauth) ([source](sdks/terraform)) |

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

Report vulnerabilities privately to support@glincker.com or through the GitHub advisory form. Do not open a public issue. Details in [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)

## Made by GLINCKER

theAuth is built in the open by [GLINCKER](https://glincker.com), a [GLINR STUDIOS](https://glinr.com) company. Founder: [thegdsks](https://thegdsks.com). Sibling projects: [LevelRail](https://levelrail.com), [theSVG](https://thesvg.org), [GLINUI](https://glinui.com).
