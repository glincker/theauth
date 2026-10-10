# @glinr/theauth-cli

## 0.3.2

### Patch Changes

- Updated dependencies [1fa2338]
- Updated dependencies [1fa2338]
- Updated dependencies [1fa2338]
- Updated dependencies [1fa2338]
  - @glinr/theauth@0.7.1
  - @glinr/theauth-hono@5.0.1

## 0.3.1

### Patch Changes

- 8997cae: Package metadata: add `engines` (Node 20+) and npm provenance to `publishConfig`, refresh the CLI description and keywords, and document MCP client setup in the gateway README.

## 0.3.0

### Minor Changes

- 4e37e17: Make theAuth easy for AI coding assistants to install and use.

  - New `theauth mcp` command: a stdio MCP server with read-only `search_docs`, `get_doc`, `add_plugin`, `generate_schema` and `inspect` tools. `inspect` never returns secret values.
  - New `theauth init --agent` (with `--target`, `--dry-run`, `--force`): writes the theAuth skill and an MCP server entry for Claude Code, Cursor and VS Code, merging into existing config.
  - The CLI build now bundles the skill and a docs search index into `dist/assets`.

- 4e37e17: Add an opt-in tamper-evident audit trail. `audit: { tamperEvident: true, hmacKey }` links each audit row to the previous one with a SHA-256 or HMAC hash, one chain per agent. New `theauth.audit.verifyAuditChain`, `replayAgent` and `exportAudit` (JSONL plus a signed manifest), a `verifyAuditExport` helper, and `theauth audit verify` / `theauth audit replay` in the CLI. `theauth_audit_logs` gains nullable `chain_seq`, `prev_hash` and `hash` columns and a unique index on `(agent_id, chain_seq)`; `createTables` adds them to existing databases and old rows are left alone. Nothing changes unless you turn it on.
- 4e37e17: Feature-gap pass, all additive.

  - Unified OTP: `createOtpService` for email and SMS with purposes (sign-in, verify-email, reset-password, two-factor), resend cooldown, attempt lockout and constant-time checks. Senders: `emailOtpSender` (wraps any email provider), `twilioOtpSender`, `consoleOtpSender`. The email OTP and phone modules gain `resendCooldownSeconds`, and email OTP now compares hashes in constant time.
  - Email adapters: `ses` (SigV4 over fetch) and `postmark`. `resend`, `sendgrid` and `smtp` are now exported from `@glinr/theauth/auth`.
  - OAuth presets: Keycloak, Authentik, ZITADEL, OneLogin, Gitea, Patreon, Box, Yandex and WordPress.com. `genericOIDC` gains `mapProfile` and `userinfoAuthScheme`.
  - CLI: `theauth doctor` (with `--json`), `theauth secret` and `theauth completions`.

- 4e37e17: Add an opt-in migration toolkit under `@glinr/theauth/migrate`. Importers for Auth0, Keycloak, Clerk, Better Auth, Auth.js and generic CSV or JSON feed one `importUsers` call with a dry run, idempotent re-runs and conflict policies. Lazy password migration verifies PBKDF2, scrypt and (with a verifier you pass) bcrypt or argon2 hashes on first login, then rehashes. `externalIssuers` accepts tokens from an existing OIDC provider with issuer, audience and algorithm pinning and a rotating JWKS cache, with optional just in time provisioning. A sticky percentage and cohort rollout (`percent: 0` is the rollback switch), a login onboarding hook that falls back to the incumbent on any failure, a shadow mode that never enforces, and a counts-only progress report. `theauth migrate plan | import | verify | status` replaces the old placeholder message. Nothing changes unless you call it.
- 4e37e17: Add a permission simulator. `createSimulator()` answers "what would this agent be allowed to do?" with a decision (`allow`, `deny`, `needs_approval`), reasons and a step by step trace, without writing audit rows or touching rate and budget state. It supports what-if overrides (extra permissions, other delegation chains, a budget cost), `simulateMany` for agent by action matrices, and `effectivePermissions`. The opt-in `simulator()` plugin mounts the admin-only `POST /agents/:id/simulate`, and the CLI gains `theauth simulate` and `theauth permissions`. Resource matching and constraint evaluation moved into shared helpers in `policy/abac.ts` so `authorize()` and the simulator run the same code; `authorize()` behavior is unchanged.
- 20aafa0: Pluggable secondary storage, hardened device auth, CLI login, agent registration tokens.

  - New `secondaryStorage` config with memory, database, Cloudflare KV, Redis-compatible and custom adapters, plus per-feature overrides. `kvStore`, `KVStore` and `RateLimitStore` keep working.
  - Security: `rateLimit()` no longer trusts `x-forwarded-for` by default. Set `trustedProxyCount` or `trustedHeader`. Behind a proxy without either, all clients share one bucket.
  - Security: device authorization takes the approving user from the authenticated session, never from the request body. The approval endpoint rejects cross-origin and non-JSON requests.
  - Device codes are stored hashed, user code guessing is limited per user, `slow_down` persists, and a granted code can be exchanged once. The token endpoint returns an `access_token` when a session manager or `issueToken` is configured.
  - `rateLimit()` now covers `/mcp/token`, `/mcp/register` and the device endpoints, with an optional per `client_id` key. `theauth.plugins.runRequestHooks()` is new, and `plugins.handleRequest` now runs `onRequest` hooks (they were collected but never invoked).
  - CLI: `theauth login`, `logout`, `whoami` and an exported `loginWithDeviceFlow` helper.
  - New `agentRegistration()` plugin: one-time, scoped, expiring tokens that let a headless agent register itself.

### Patch Changes

- 4e37e17: Security: the framework adapters no longer serve the management routes anonymously.

  BREAKING (adapters): `/agents`, `/delegations`, `/audit`, `/dashboard` and `POST /authorize` now require an authenticated caller. Pass `authenticate: (request) => ({ id }) | null` to the adapter, or configure `auth.session` on `createTheAuth` to accept any valid session. With neither, the adapter throws when it is created. For local development only, `allowUnauthenticated: true` restores the old behavior and logs a warning. `/authorize/token`, MCP, password reset, email verification and plugin routes are unchanged.

  Other fixes:

  - hono and fastify: plugin routes now work when the adapter is mounted under a prefix (`app.route("/x", theAuthHono(...))`, `register(plugin, { prefix })`) instead of returning 404.
  - core: `plugins: [magicLink(...)]` (and the email OTP, 2FA, passkey, API key and organization plugins) now create their tables, matching the config-key form.
  - core: new `createAdapterGuard` and `isProtectedAdapterPath` exports used by every adapter.
  - create-theauth-app: templates pin `@glinr/*` packages to the versions in this release instead of stale ranges, list `sql.js` (the driver behind `provider: "sqlite"`) and `zod`, and the hono-mcp template protects its management routes with an `ADMIN_API_KEY`. The next-saas catch-all route now passes the TheAuth instance to the adapter.

- Updated dependencies [4e37e17]
- Updated dependencies [4e37e17]
- Updated dependencies [4e37e17]
- Updated dependencies [4e37e17]
- Updated dependencies [4e37e17]
- Updated dependencies [36f15a3]
- Updated dependencies [4e37e17]
- Updated dependencies [4e37e17]
- Updated dependencies [4e37e17]
- Updated dependencies [4e37e17]
- Updated dependencies [20aafa0]
  - @glinr/theauth@0.7.0
  - @glinr/theauth-hono@5.0.0

## 0.2.0

### Minor Changes

- 02a8500: Add `theauth codemod rename`, a dry-run-by-default codemod that migrates `Kavach*` identifiers, old import paths and `KAVACH_*` env vars to their TheAuth names, and reports `X-Kavach-` headers, `kavach_` table names and other leftover mentions for manual review. Pass `--write` to apply and `--include-env` to also rewrite `.env*` files and docs.
- 0fa5b1e: Remove the legacy KavachOS naming. The deprecated `Kavach*` and `createKavach` exports are gone: use `TheAuth*` and `createTheAuth`. Environment variables are now `THEAUTH_*`, webhook headers `X-TheAuth-*`, cookies and the default API route use `theauth`, and database tables are `theauth_*` (existing `kavach_*` tables are renamed in place by `createTables`, no data is lost). `Auth*` aliases remain deprecated.

### Patch Changes

- Updated dependencies [960fe89]
- Updated dependencies [dfd31f9]
- Updated dependencies [5e53bdb]
- Updated dependencies [0fa5b1e]
- Updated dependencies [9861742]
  - @glinr/theauth@0.6.0
  - @glinr/theauth-hono@4.0.0

## 0.1.5

### Patch Changes

- Updated dependencies
  - @glinr/theauth@0.5.0
  - @glinr/theauth-hono@4.0.0

## 0.1.4

### Patch Changes

- Updated dependencies
  - theauth@0.4.2
  - @glinr/theauth-hono@3.0.2

## 0.1.3

### Patch Changes

- Updated dependencies
  - theauth@0.4.1
  - @glinr/theauth-hono@3.0.1

## 0.1.2

### Patch Changes

- Updated dependencies
  - theauth@0.4.0
  - @glinr/theauth-hono@3.0.0

## 0.1.1

### Patch Changes

- Updated dependencies
  - theauth@0.3.0
  - @glinr/theauth-hono@2.0.0

## 0.1.0

### Minor Changes

- 94804ec: Launch release: promote core and primary client-facing packages to the 0.1 line.

  Highlights:

  - Stabilize package exports and build artifacts for launch.
  - Ship improved CLI version handling and launch docs.
  - Keep adapters/plugins/dashboard on existing release tracks for a separate coordinated versioning pass.

### Patch Changes

- Updated dependencies [94804ec]
- Updated dependencies [94804ec]
  - theauth@0.1.0
  - @glinr/theauth-hono@1.0.0
