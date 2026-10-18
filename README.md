<p align="center">
  <img src="https://theauth.dev/logo.svg" height="64" alt="theAuth" />
</p>

<h1 align="center">theAuth</h1>

<p align="center"><strong>Open-source auth where AI agents are first class.</strong><br>
Agent identity, delegation with live revocation and an MCP OAuth 2.1 server, next to the usual human sign in. One TypeScript library, self-hosted, MIT licensed.</p>

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

theAuth is auth for products where AI agents act on behalf of people. Each agent gets its own identity and a bearer token, scoped permissions, an owner, and an audit row for every decision. An agent can hand a subset of its permissions to another agent, and revoking any link in that chain takes effect on the next call. It includes an OAuth 2.1 authorization server for MCP, and the usual human sign in: email and password, magic links, passkeys, TOTP, 48 OAuth providers, SAML and OIDC SSO, SCIM.

It runs on Node, Bun, Deno and Cloudflare Workers with four runtime dependencies (`drizzle-orm`, `jose`, `sql.js`, `zod`). No hosted service is required. The project was called kavachOS until 2026, see the [rename map](RENAME-MAP.md) if you have older code.

Devices and robots use the same model. A sensor, gateway or machine can hold its own credentials (a pre shared key, a signing key or a TLS client certificate), enroll with a claim code or a bulk token, and be revoked live. For ROS 2, `theauth ros2 export` writes the SROS2 and DDS Security files from the robot's permissions, and a gate node asks theAuth before a hazardous command is published. theAuth is not a safety system, so emergency stops stay in the robot's safety controller.

## Quickstart

Needs Node 20 or newer. This runs as pasted, with an in-memory SQLite database.

```bash
npm install @glinr/theauth
```

```typescript
import { createTheAuth } from "@glinr/theauth";

const auth = await createTheAuth({
  database: { provider: "sqlite", url: ":memory:" },
  agents: { enabled: true },
});

// An agent needs an owner row. Human sign in creates these for you.
const owner = await auth.user.create({ email: "owner@example.com", name: "Owner" });

const agent = await auth.agent.create({
  ownerId: owner.id,
  name: "github-reader",
  type: "autonomous",
  permissions: [{ resource: "mcp:github:*", actions: ["read"] }],
});
console.log(agent.token); // starts with "ta_", shown once

const read = await auth.authorize(agent.id, { action: "read", resource: "mcp:github:repos" });
console.log(read.allowed, read.code);

const write = await auth.authorize(agent.id, { action: "write", resource: "mcp:github:repos" });
console.log(write.allowed, write.code);
```

Output from a real run (the token differs each time):

```text
ta_2_wqD8Yoenc_LDoFMTdKkQ9YXQNuW-rWxHHyfmKJJOo
true allowed
false no_permission
```

Tokens from before the rename start with `kv_` and are still accepted. To serve this over HTTP, add a [framework adapter](#framework-adapters). For email and password, install `@glinr/theauth-email`. To scaffold an app, run `npm create @glinr/theauth-app`. Full walkthrough: [quickstart](https://docs.theauth.dev/quickstart).

## What makes it different

- **Delegation chains with live revocation.** An agent delegates part of what it holds to another agent, with depth limits and expiry. If a delegator is revoked, suspended or expired, the agents below it stop borrowing its permissions. See [delegation](https://docs.theauth.dev/delegation).
- **MCP tokens bound to their authority.** Tokens from token exchange carry the agent path and delegation link ids. Revoking a link, an agent, a session or a single token fails the next MCP request on every instance that shares the database. Three freshness modes trade latency for staleness: [MCP revocation](https://docs.theauth.dev/mcp-revocation).
- **Hooks that fail closed.** A `beforeAuthorize` hook that throws, times out (2000 ms by default) or returns a malformed verdict denies the call. You can plug in an external guard over HTTPS with signed requests and responses: [hooks](https://docs.theauth.dev/hooks), [remote guards](https://docs.theauth.dev/guards).
- **Decision codes and explain.** `authorize()` returns a machine-readable `code` such as `no_permission` or `hook_denied`. `explain()` says which rule or delegation link carried a call, with no side effects: [explain](https://docs.theauth.dev/explain), [errors](https://docs.theauth.dev/errors).
- **Tamper-evident audit.** Turn on the hash chain and an edited, deleted or reordered row shows up on the next verify. Signed checkpoints and receipts can be checked offline, including by the Go library: [audit trail](https://docs.theauth.dev/audit-trail), [receipts](https://docs.theauth.dev/audit-receipts).

## Status

Maturity follows the package version: stable is 1.0 or later, beta is 0.2 to 0.9, experimental is 0.1. The core package is at 1.3.0. The 2.0 changes are queued as changesets, so read [Upgrading to 2.0](https://docs.theauth.dev/upgrading-to-2) if you run 1.x.

What you should know before relying on it:

- **SAML is experimental.** The verifier is our own code, built on Web Crypto. It passes tests against xmllint and xml-crypto output and has had no independent audit. If you need an audit today, put an audited SAML library in front and pass the identity to your own session code.
- **The cookie session cache is experimental and opt in.** It can lag a revocation by up to its `maxAge`. See [session hardening](https://docs.theauth.dev/session-hardening).
- **MySQL is not supported.** `provider: "mysql"` throws unless you pass `experimental: true`, and the baseline schema does not apply on a real server yet.
- **Postgres is tested by hand, not in CI.** The full suite runs against Postgres 14 before each release. Only the `pg` driver is supported.
- **D1 is not tested in CI or by hand yet.** The generated SQLite SQL is applied with `skipMigrations: true`.
- **Client ID metadata documents (CIMD) on Workers and Deno.** Deno uses `node:dns` like Node. Workers need `createDohResolver()`, or `"none"` with `allowedHosts`. DNS rebinding cannot be fully closed without `allowedHosts`. See [CIMD](https://docs.theauth.dev/mcp-client-id-metadata).

### Supported databases

| Provider | Use it for | Tested in CI |
|---|---|---|
| `sqlite` (sql.js) | Tests, CI, demos. In memory only. | Yes |
| `sqlite-native` (better-sqlite3) | One process, a database file on disk. | Yes |
| `postgres` (`pg`) | Several instances or real traffic. | No, run by hand |
| `d1` | Cloudflare Workers. | No |
| `mysql` | Not supported. | No |

The Prisma adapter reads and writes theAuth tables from code that already uses Prisma. Picking a store and a secondary store: [choose storage](https://docs.theauth.dev/choose-storage).

## Packages

All packages live in this monorepo and publish under `@glinr/`. Versions come from each `package.json`.

| Package | Version | Maturity | What it does |
|---|---|---|---|
| [`theauth`](packages/core) | 1.3.0 | Stable | Agent identity, delegation, MCP OAuth 2.1 server, DPoP, passkeys, audit |
| [`theauth-email`](packages/auth/email) | 4.1.0 | Stable | Email and password sign in |
| [`theauth-mcp`](packages/mcp) | 1.2.0 | Stable | Read-only MCP server to inspect agents, permissions and audit |
| [`theauth-gateway`](packages/gateway) | 4.1.0 | Stable | Auth proxy in front of any API or MCP server |
| [`theauth-cli`](packages/cli) | 1.2.0 | Stable | `init`, `doctor`, migrations, dashboard (also `npx theauth`) |
| [`theauth-client`](packages/client) | 1.1.1 | Stable | TypeScript client for the REST API |
| [`theauth-plugin-discovery`](packages/plugins/discovery) | 4.0.1 | Stable | A2A agent card discovery |
| [`theauth-plugin-telemetry`](packages/plugins/telemetry) | 4.0.0 | Stable | OpenTelemetry spans from auth events |
| [`theauth-react`](packages/react) | 0.7.1 | Beta | React hooks |
| [`theauth-vue`](packages/vue) | 0.3.0 | Beta | Vue 3 composables |
| [`theauth-svelte`](packages/svelte) | 0.3.0 | Beta | Svelte stores |
| [`theauth-expo`](packages/expo) | 0.4.0 | Beta | React Native and Expo client |
| [`theauth-electron`](packages/electron) | 0.3.0 | Beta | Electron client |
| [`theauth-ui`](packages/ui) | 0.3.0 | Beta | Prebuilt auth components |
| [`theauth-ui-headless`](packages/ui-headless) | 0.2.0 | Beta | Unstyled account components |
| [`theauth-dashboard`](packages/dashboard) | 0.3.0 | Beta | Admin UI for agents, permissions and audit |
| [`theauth-agent-frameworks`](packages/agent-frameworks) | 0.2.0 | Beta | Tool guard with human approval for LangChain.js, LangGraph and Mastra |
| [`theauth-conformance`](packages/conformance) | 0.2.0 | Beta | Black-box conformance suite for OAuth 2.1 and MCP servers |
| [`theauth-test-utils`](packages/test-utils) | 0.2.0 | Beta | Mock providers, factories and assertions |
| [`create-theauth-app`](packages/create-theauth-app) | 0.5.0 | Beta | Scaffold an app |
| [`theauth-extension`](packages/extension) | 0.1.0 | Experimental | OAuth 2.1 for Manifest V3 browser extensions |

Other languages: a [Go client](sdks/go) and a [Python client](https://pypi.org/project/theauth/) ([source](sdks/python)) for this REST API, both checked against the generated [`sdks/openapi.json`](sdks/openapi.json), and a [Terraform provider](https://registry.terraform.io/providers/glincker/theauth) ([source](sdks/terraform)). [theauth-go](https://github.com/glincker/theauth-go) is a different thing: the Go server library (v2), not a client for this API.

### Framework adapters

Every adapter wraps one core handler, so all of them serve the same routes with the same status codes ([route reference](https://docs.theauth.dev/adapters/routes)).

| Adapter | Version | Docs |
|---|---|---|
| [`theauth-hono`](packages/adapters/hono) | 5.1.0 | [Hono](https://docs.theauth.dev/adapters/hono) |
| [`theauth-nextjs`](packages/adapters/nextjs) | 5.1.0 | [Next.js](https://docs.theauth.dev/adapters/nextjs) |
| [`theauth-express`](packages/adapters/express) | 5.1.0 | [Express](https://docs.theauth.dev/adapters/express) |
| [`theauth-fastify`](packages/adapters/fastify) | 5.1.0 | [Fastify](https://docs.theauth.dev/adapters/fastify) |
| [`theauth-nestjs`](packages/adapters/nestjs) | 5.1.0 | [NestJS](https://docs.theauth.dev/adapters/nestjs) |
| [`theauth-nuxt`](packages/adapters/nuxt) | 5.1.0 | [Nuxt](https://docs.theauth.dev/adapters/nuxt) |
| [`theauth-sveltekit`](packages/adapters/sveltekit) | 5.1.0 | [SvelteKit](https://docs.theauth.dev/adapters/sveltekit) |
| [`theauth-astro`](packages/adapters/astro) | 5.1.0 | [Astro](https://docs.theauth.dev/adapters/astro) |
| [`theauth-solidstart`](packages/adapters/solidstart) | 5.1.0 | [SolidStart](https://docs.theauth.dev/adapters/solidstart) |
| [`theauth-tanstack`](packages/adapters/tanstack) | 5.1.0 | [TanStack Start](https://docs.theauth.dev/adapters/tanstack) |
| [`theauth-prisma`](packages/adapters/prisma) | 4.0.0 | [Prisma](https://docs.theauth.dev/prisma) |
| [`theauth-nextjs-auth`](packages/adapters/nextjs-auth) | 0.2.0 (beta) | Next.js client for external auth backends |

Mounting Hono, for example:

```typescript
import { Hono } from "hono";
import { createTheAuth } from "@glinr/theauth";
import { theAuthHono } from "@glinr/theauth-hono";

const auth = await createTheAuth({
  database: { provider: "postgres", url: process.env.DATABASE_URL! },
});

const app = new Hono();
app.route("/api/theauth", theAuthHono(auth, { authenticate }));
```

`authenticate` resolves the caller from the request, see the [Hono guide](https://docs.theauth.dev/adapters/hono). Working examples are in [`examples/`](examples).

## Docs

- [Quickstart](https://docs.theauth.dev/quickstart) and [core concepts](https://docs.theauth.dev/concepts)
- [MCP OAuth 2.1 server](https://docs.theauth.dev/mcp) and [MCP revocation](https://docs.theauth.dev/mcp-revocation)
- [Delegation](https://docs.theauth.dev/delegation), [guards](https://docs.theauth.dev/guards) and [hooks](https://docs.theauth.dev/hooks)
- [Observability](https://docs.theauth.dev/observability), [audit trail](https://docs.theauth.dev/audit-trail) and [audit receipts](https://docs.theauth.dev/audit-receipts)
- [IoT devices](https://docs.theauth.dev/iot-devices) and [robotics and ROS 2](https://docs.theauth.dev/robotics-ros2)
- [Upgrading to 2.0](https://docs.theauth.dev/upgrading-to-2) for people on 1.x
- [Works with](https://docs.theauth.dev/works-with), [migrating from another library](https://docs.theauth.dev/migrate/choose-a-path) and the [API reference](https://docs.theauth.dev/api)
- [Security policy](SECURITY.md)

## By the numbers

Generated by `node scripts/stats.mjs` into [`docs/stats.json`](docs/stats.json).

- 48 OAuth providers: 22 first class and 26 presets
- 10 framework adapters
- 4 runtime dependencies in core
- About 5,277 test cases in 410 test files (a textual count of `it(` and `test(` calls, so approximate)

## Community and contributing

Questions and ideas go to [GitHub Discussions](https://github.com/glincker/theauth/discussions) or the `#theauth` channel in the [GLINR Discord](https://discord.gg/Ar5pcaZB99). Changes are listed in [CHANGELOG.md](CHANGELOG.md). To contribute, see [CONTRIBUTING.md](CONTRIBUTING.md); everyone is held to the [Code of Conduct](CODE_OF_CONDUCT.md).

Report vulnerabilities privately to support@glinr.com or through the GitHub advisory form. Do not open a public issue. Details in [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE). Built in the open by [GLINCKER](https://glincker.com), a [GLINR STUDIOS](https://glinr.com) company.
