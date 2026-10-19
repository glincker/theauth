# @glinr/create-theauth-app

## 0.6.0

### Minor Changes

- a561306: `theauth init` and `theauth doctor` rebuilt, and the project templates moved to real storage.

  `theauth init` now detects the framework and package manager from `package.json` and writes a working setup: `src/theauth.ts`, a seed script that creates the owner user with `theauth.user.create` before a demo agent (the old example created an agent for a user that did not exist and failed on the foreign key), the mount file for Hono, Express, Fastify, Next.js, SvelteKit or Nuxt, `.env.example`, and a `.env` with generated secrets (added to `.gitignore`). It stores data in a SQLite file, not `:memory:`, and prints a `curl` against the mounted routes. Re-running it never overwrites a file that exists unless you pass `--force`.

  `theauth doctor` adds `core-version` (core against the adapter peer range), `schema` (pending migrations from the ledger), `allow-unauthenticated` and `trusted-proxy`. `theauth doctor --live <url>` calls the running server: routes reachable, MCP metadata only lists mounted endpoints, and a protected route answers 401 without a token. The `--json` shape is unchanged (`{ ok, checks }`); new checks only add entries.

  Upgrade notes:

  - `theauth init` flags changed: `--framework`, `--db`, `--yes`, `--dir`, `--force`, `--mcp`. It no longer writes `theauth.config.ts` or `theauth.example.ts`. `--mcp` is accepted and skipped with a note until the database backed MCP stores exist.
  - `create-theauth-app` templates (`hono-mcp`, `next-saas`, `cloudflare-workers`) write a `.env` (or `.dev.vars`) with generated secrets, drop the hard coded dev secrets, create the owner with `user.create`, and add a `doctor` script. SQLite templates now depend on `better-sqlite3` and `provider: "sqlite-native"`, because the `sql.js` provider does not persist its file. The Cloudflare template requires `ADMIN_API_KEY` instead of `allowUnauthenticated`.
  - The `hono-mcp` template still keeps MCP clients, codes and tokens in memory. Database backed MCP stores are not available yet.

- a561306: Database backed MCP authorization server, OAuth client to agent binding, and readable denials.

  **What is new**

  - `createMcpModule({ auth, config, resolveUserId })` keeps clients, authorization codes, access and refresh token records and refresh token families in the TheAuth database, so several instances share state and a restart keeps registered clients. Authorization codes are consumed with a single `DELETE ... RETURNING` (one winner under concurrency). Any store function you also pass wins over the database one, and the old form with seven store functions still works for tests and custom storage. `createMcpStores(db)` returns the database stores as an object.
  - Migration `0006` adds `agent_id`, `scope`, `logo_uri`, `jwks`, `jwks_uri`, `user_id` and `source` to `theauth_oauth_clients`, and `jti`, `family_id`, `token_type` and `dpop_jkt` (with indexes on `jti`, `client_id` and `family_id`) to `theauth_oauth_access_tokens`. `agent_id` references `theauth_agents(id)` with `ON DELETE SET NULL` when agents are enabled. Configs with an `mcp` key now also create the oauth tables and the refresh token family tables.
  - `mcp.clients.bindAgent(clientId, agentId)`, `unbindAgent` and `agentFor` bind an OAuth client to an agent. Tokens issued to a bound client carry `agent_id` without `agentClaims`. `registration.agentForClient(client, request)` binds at registration (server side only), and `preRegisteredClients[].agentId` binds at startup. `mcp.registerClient(body, request?)` takes the request.
  - With `auth`, the live delegation check resolves each actor to the agent its client is bound to, then to its own id, so the hand written `resolveActorAgentId` is only needed for the token subject (a user). Your resolver runs first and falls through to the built-in mapping when it returns `undefined`.
  - `requireScopes` returns a typed result: `{ authorized: false, status, error: { code, message }, rejected?, response }`. `error.code` is one of `UNAUTHORIZED`, `INVALID_TOKEN`, `TOKEN_EXPIRED`, `INVALID_AUDIENCE`, `INVALID_ISSUER`, `DELEGATION_REVOKED`, `INSUFFICIENT_SCOPE`, `DPOP_REQUIRED`, `SERVER_ERROR`. `rejected` (`clientId`, `subject`, `agentId?`, `tokenId`) is set only for a token whose signature verified, so a denial can be attributed in an audit log.
  - The MCP HTTP responses follow the MCP authorization spec: 401 carries `WWW-Authenticate: Bearer [error="invalid_token", error_description="..."], resource_metadata="...", scope="..."` (no `error` when no token was sent), and the 403 `insufficient_scope` step-up challenge now includes `resource_metadata` and a `code` field in its body. `requireMcpAuth` adds `scope` to its 401 challenges when `requiredScopes` is set.
  - The `hono-mcp` template uses the database stores, binds clients through `PUT /admin/mcp-clients/:clientId/agent`, and protects its tools with `mcp.requireScopes`.

  **Upgrade notes (breaking)**

  - The 401 body from `buildUnauthorizedResponse`, `requireScopes` and `createMcpResponseHelpers(ctx).unauthorizedResponse` is now `{ jsonrpc, error: { code: -32001, message, data: { code } }, id: null }`. The JSON-RPC error code changed from `-32000` to `-32001`, and the `www-authenticate` key inside the body is gone: read the `WWW-Authenticate` header instead.
  - `requireScopes` failures gain `status`, `error` and `rejected`. Code that only read `check.response` keeps working; code that matched the type `{ authorized: false; response }` exactly needs the wider `RequireScopesResult`.
  - Expired tokens now report `TOKEN_EXPIRED` (before, the validator mapped them to `INVALID_TOKEN` because it matched the wrong jose message). Wrong audience and issuer keep their codes.
  - `McpAuthContext` and `McpClient` gained optional members (`setClientAgent`, `agentId`). Custom store implementations need no change.

## 0.5.0

### Minor Changes

- bf41bbb: Add `theauth dev` (zero-config local first run), a Cloudflare Workers template, an opt-in `adminApi` plugin with an admin MCP server (read-only by default, writes gated by approval), a black-box agent-auth conformance suite, and LangGraph and Mastra approval wrappers.

  Breaking behavior in the gateway: the client `Authorization` and `DPoP` headers are no longer forwarded to the upstream by default. Opt out with `--forward-auth` or `stripAuthHeader: false`. The gateway also gains an MCP mode, a 10 MiB request body limit, a 30 second upstream header timeout, and hop-by-hop and `X-Forwarded-*` header handling. Core gains a browser-safe `@glinr/theauth/browser` entry.

## 0.4.0

### Minor Changes

- 4e37e17: Security: the framework adapters no longer serve the management routes anonymously.

  BREAKING (adapters): `/agents`, `/delegations`, `/audit`, `/dashboard` and `POST /authorize` now require an authenticated caller. Pass `authenticate: (request) => ({ id }) | null` to the adapter, or configure `auth.session` on `createTheAuth` to accept any valid session. With neither, the adapter throws when it is created. For local development only, `allowUnauthenticated: true` restores the old behavior and logs a warning. `/authorize/token`, MCP, password reset, email verification and plugin routes are unchanged.

  Other fixes:

  - hono and fastify: plugin routes now work when the adapter is mounted under a prefix (`app.route("/x", theAuthHono(...))`, `register(plugin, { prefix })`) instead of returning 404.
  - core: `plugins: [magicLink(...)]` (and the email OTP, 2FA, passkey, API key and organization plugins) now create their tables, matching the config-key form.
  - core: new `createAdapterGuard` and `isProtectedAdapterPath` exports used by every adapter.
  - create-theauth-app: templates pin `@glinr/*` packages to the versions in this release instead of stale ranges, list `sql.js` (the driver behind `provider: "sqlite"`) and `zod`, and the hono-mcp template protects its management routes with an `ADMIN_API_KEY`. The next-saas catch-all route now passes the TheAuth instance to the adapter.

## 0.3.0

### Minor Changes

- 0fa5b1e: Remove the legacy KavachOS naming. The deprecated `Kavach*` and `createKavach` exports are gone: use `TheAuth*` and `createTheAuth`. Environment variables are now `THEAUTH_*`, webhook headers `X-TheAuth-*`, cookies and the default API route use `theauth`, and database tables are `theauth_*` (existing `kavach_*` tables are renamed in place by `createTables`, no data is lost). `Auth*` aliases remain deprecated.

## 0.2.0

### Minor Changes

- Add the `hono-mcp` template. Scaffolds a Hono server that mounts the TheAuth auth routes and the MCP OAuth 2.1 surface under `/api`, with `/tools/list` and `/tools/call/:name` behind `authorizeByToken` or MCP JWT validation. Complements the existing `next-saas` template with an agent-first starter.

  The `expo-mobile` template stays behind its placeholder.

## 0.1.0

### Minor Changes

- feat: v3 wave

  - Agentic JWT claim constants (`AGENTIC_JWT_CLAIMS`) from `draft-goswami-agentic-jwt-00` and `draft-liu-agent-operation-authorization-01`, behind a new `emitAgenticJwtClaims` config flag. Populates `agent_id`, `agent_type`, and `trust_tier` on issued tokens when on. Off by default.
  - Ten OAuth providers (Notion, Spotify, Discord, Slack, Twitch, Reddit, Figma, Dropbox, Zoom, Atlassian) promoted to first-class named exports with typed factories, `DEFAULT_X_SCOPES` constants, and profile normalisers.
  - `exportAuditAsVC` in `@glinr/theauth/vc` for compliance audit exports as W3C Verifiable Credentials (`ldp_vc` or `jwt_vc`, individual or Verifiable Presentation).
  - Initial `@glinr/create-theauth-app` scaffolder on npm with a Next.js App Router template.
