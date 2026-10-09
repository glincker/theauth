---
name: theauth
description: Install and use theAuth (@glinr/theauth), the TypeScript auth SDK for AI agents and humans. Use when adding agent identity, scoped permissions, delegation, audit logs, human sign-in plugins, or an MCP OAuth 2.1 authorization server to a Node, Bun, Deno or edge project.
---

# theAuth

theAuth is a TypeScript SDK where the AI agent is the primary identity. Each agent has an owner (a user row), a bearer token, scoped permissions, optional delegation to sub-agents, and an audit row for every decision. Human sign-in comes from plugins. An MCP OAuth 2.1 authorization server is available through `@glinr/theauth/mcp`.

Docs: https://docs.theauth.dev (full text at https://docs.theauth.dev/llms-full.txt). If the `theauth` MCP server is connected, prefer its `search_docs`, `get_doc`, `add_plugin` and `inspect` tools over guessing.

## Before you change anything

1. Look for an existing setup: search for `createTheAuth(` or call the `inspect` tool. Extend it, do not add a second instance.
2. Never print or commit secrets. Session and MCP signing secrets come from environment variables.
3. Verify against the docs page or the installed types. Do not invent options.

## Install

```bash
pnpm add @glinr/theauth better-sqlite3
```

`npm install` and `yarn add` work the same. Use the matching database provider on Bun, Deno or Workers (see https://docs.theauth.dev/database). Tables are created on startup.

## Create the instance

```ts
import { createTheAuth } from "@glinr/theauth";

export const theauth = await createTheAuth({
  database: { provider: "sqlite", url: "theauth.db" }, // or { provider: "postgres", url: process.env.DATABASE_URL! }
  agents: { enabled: true, maxPerUser: 10, auditAll: true, tokenExpiry: "24h" },
});
```

Create it once at startup and reuse it. Functions that can fail return `{ success: true, data } | { success: false, error }` in several modules, so check `success` rather than assuming a throw.

## Adapter choice

Pick the adapter for the framework already in the project. Each returns the routes (agents, delegations, audit, authorize, MCP) for you to mount.

| Framework | Install | Mount |
|---|---|---|
| Hono | `@glinr/theauth-hono` | `app.route("/api/theauth", theAuthHono(theauth, { authenticate }))` |
| Express | `@glinr/theauth-express` | `app.use("/api/theauth", theAuthExpress(theauth, { authenticate }))` |
| Fastify | `@glinr/theauth-fastify` | `fastify.register(theAuthFastify(theauth, { authenticate }), { prefix: "/api/theauth" })` |
| Next.js | `@glinr/theauth-nextjs` | `const handlers = theAuthNextjs(theauth, { authenticate })` in `app/api/theauth/[...theauth]/route.ts`, then export `GET`, `POST`, `PATCH`, `DELETE`, `OPTIONS` from it |

Other adapters: Astro, NestJS, Nuxt, SolidStart, SvelteKit, TanStack (see https://docs.theauth.dev/adapters).

The adapters refuse to start without a way to authenticate callers on the management routes. Pass `authenticate`, configure `auth.session`, or set `allowUnauthenticated: true` for local development only:

```ts
const authenticate = async (request: Request) => {
  const user = await theauth.auth.resolveUser(request);
  return user ? { id: user.id } : null;
};
```

## Agent identity, permissions, audit

```ts
const agent = await theauth.agent.create({
  ownerId: "user-123", // must exist in theauth_users
  name: "github-reader",
  type: "autonomous", // or "delegated" | "service"
  permissions: [{ resource: "mcp:github:*", actions: ["read"] }],
});
// agent.token starts with "kv_" and is shown once. Store it in a secrets manager.

const decision = await theauth.authorize(agent.id, { action: "read", resource: "mcp:github:repos" });
if (!decision.allowed) throw new Error(`Denied: ${decision.reason}`);

// With only a bearer token from an incoming request:
await theauth.authorizeByToken(agent.token, { action: "read", resource: "mcp:github:repos" });

const logs = await theauth.audit.query({ agentId: agent.id });
const rotated = await theauth.agent.rotate(agent.id); // old token stops working immediately
```

Constraints such as `requireApproval: true` and `maxCallsPerHour` go in a permission's `constraints`. Resources support `*` wildcards.

## Delegation

An agent can pass a subset of its own permissions to another agent. Escalation is rejected.

```ts
const sub = await theauth.agent.create({ ownerId: "user-123", name: "sub-reader", type: "delegated", permissions: [] });
await theauth.delegate({
  fromAgent: agent.id,
  toAgent: sub.id,
  permissions: [{ resource: "mcp:github:issues", actions: ["read"] }],
  expiresAt: new Date(Date.now() + 3_600_000),
  maxDepth: 2,
});
const effective = await theauth.delegation.getEffectivePermissions(sub.id);
```

## Plugins (human auth and extras)

Pass plugins to `createTheAuth({ plugins: [...] })`. Plugins that issue sessions (`magicLink`, `emailOtp`, `anonymousAuth`) throw at startup unless `auth: { session: { secret: process.env.THEAUTH_SESSION_SECRET! } }` is set (32+ characters).

```ts
import { createTheAuth, passkey, twoFactor, organization } from "@glinr/theauth";
import { emailPassword } from "@glinr/theauth-email"; // pnpm add @glinr/theauth-email

const theauth = await createTheAuth({
  database: { provider: "sqlite", url: "theauth.db" },
  auth: { session: { secret: process.env.THEAUTH_SESSION_SECRET! } },
  plugins: [
    emailPassword({
      appUrl: process.env.APP_URL!,
      sendVerificationEmail: async (email, _token, url) => sendMail(email, "Verify your email", url),
      sendResetEmail: async (email, _token, url) => sendMail(email, "Reset your password", url),
    }),
    passkey({ rpName: "My App", rpId: "example.com", origin: "https://example.com" }),
    twoFactor(),
    organization(),
  ],
});
```

Exported from `@glinr/theauth`: `magicLink`, `emailOtp`, `passkey`, `twoFactor`, `organization`, `apiKeys`, `anonymousAuth`, `admin`, `gdpr`, `agentRegistration`, `oauth`. Email and password lives in `@glinr/theauth-email`. Plugin endpoints take standard `Request` objects: `theauth.plugins.handleRequest(request)`. Use the `add_plugin` MCP tool for the exact snippet of any of them.

Headless agents (CI, workers) can register themselves with a one-time token from the `agentRegistration()` plugin: https://docs.theauth.dev/agent-registration-tokens.

## MCP auth (OAuth 2.1 authorization server)

The OAuth server is a separate module. It has no database of its own: you supply storage callbacks (`storeClient`, `findClient`, `storeAuthorizationCode`, `consumeAuthorizationCode`, `storeToken`, `findTokenByRefreshToken`, `revokeToken`, `resolveUserId`). Copy the in-memory example from https://docs.theauth.dev/mcp and back it with a real database in production.

```ts
import { createMcpModule } from "@glinr/theauth/mcp";

export const mcp = createMcpModule({
  config: {
    enabled: true,
    issuer: process.env.AUTH_BASE_URL!,
    baseUrl: `${process.env.AUTH_BASE_URL!}/api/theauth`, // public origin plus the adapter mount path
    signingSecret: process.env.MCP_SIGNING_SECRET!, // 32+ characters
    resource: process.env.MCP_RESOURCE_URL!, // audience this server accepts
    scopes: ["mcp:read", "mcp:execute"],
    loginPage: `${process.env.AUTH_BASE_URL!}/login`,
  },
  ...mcpStore,
});
// Mount it: theAuthHono(theauth, { mcp, authenticate })
```

Protect a route:

```ts
const check = await mcp.requireScopes(request, ["mcp:read"]);
if (!check.authorized) return check.response; // 401 or 403 with the right challenge
const session = check.session; // userId, clientId, scopes, resource, expiresAt
```

Gotchas: the well-known documents are served relative to the mount point, so add root-level routes for `/.well-known/oauth-authorization-server` (`mcp.getMetadata()`) and `/.well-known/oauth-protected-resource` (`mcp.getProtectedResourceMetadata()`) when mounted under a prefix. PKCE S256 is the only challenge method. `resource` (RFC 8707) is required at the authorize and token endpoints.

## Checklist

- One `createTheAuth` instance, secrets from the environment, nothing secret committed.
- Management routes protected by `authenticate` or `auth.session`.
- Agent tokens stored once, rotated with `theauth.agent.rotate`.
- Run the project's typecheck after edits. The package ships its own types.
