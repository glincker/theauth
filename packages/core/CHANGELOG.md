# theauth

## 0.7.2

### Patch Changes

- 43fa729: Fix the quick start snippet in the package README: enable the agent tables with `agents: { enabled: true }`, await `createTheAuth`, and create the owner row first.
- 8930a06: Record denied attempts by revoked and expired agents in the audit log. `authorize()` and `authorizeByToken()` now write a `denied` row with reason `agent_revoked` or `agent_expired` for a known agent, so the attempt is visible and stays on the agent's hash chain. Decisions are unchanged. Unknown agent ids and unknown tokens still write no row.

## 0.7.1

### Patch Changes

- 1fa2338: Resolve the client IP through the trusted proxy helper.
- 1fa2338: Scope management routes to the signed in owner when the default guard is used. With the default session resolver, `/agents`, `/delegations`, `/audit`, `/dashboard` and `POST /authorize` only act on the caller's own agents, delegations and audit rows, and `POST /agents` requires `ownerId` to be the caller. A custom `authenticate` resolver behaves as before. Core adds `guard.resolve()` and the `AdapterScope` helper so the other adapters can adopt the same checks, and `audit.export()` accepts a `userId` filter.
- 1fa2338: Upgrade notes for this release. With the default session guard, a signed in user is limited to their own agents, delegations and audit rows, so an app that used the default guard as a shared admin view must pass an `authenticate` resolver that checks admin rights. The adapters and the gateway no longer read `X-Forwarded-For` or `X-Real-IP` themselves: pass `trustedProxy: { trustedProxyCount }` or `trustedProxy: { trustedHeader }` to match your proxy, otherwise an `ipAllowlist` constraint denies because the client IP is unknown. The captcha helper no longer trusts `CF-Connecting-IP` unconditionally, use `trustedProxy: { trustedHeader: "cf-connecting-ip" }` to keep it. Adapters require `@glinr/theauth` 0.7.1 or newer.
- 1fa2338: Resolve the client IP through the trusted proxy helper. The hono and express adapters no longer read `X-Forwarded-For` or `X-Real-IP` directly. By default forwarded headers are ignored (Express still falls back to `req.ip`), so an `ipAllowlist` constraint denies when the IP is unknown. Pass `trustedProxy: { trustedProxyCount }` or `trustedProxy: { trustedHeader }` to the adapter to match your proxy setup.

## 0.7.0

### Minor Changes

- 4e37e17: Security: the framework adapters no longer serve the management routes anonymously.

  BREAKING (adapters): `/agents`, `/delegations`, `/audit`, `/dashboard` and `POST /authorize` now require an authenticated caller. Pass `authenticate: (request) => ({ id }) | null` to the adapter, or configure `auth.session` on `createTheAuth` to accept any valid session. With neither, the adapter throws when it is created. For local development only, `allowUnauthenticated: true` restores the old behavior and logs a warning. `/authorize/token`, MCP, password reset, email verification and plugin routes are unchanged.

  Other fixes:

  - hono and fastify: plugin routes now work when the adapter is mounted under a prefix (`app.route("/x", theAuthHono(...))`, `register(plugin, { prefix })`) instead of returning 404.
  - core: `plugins: [magicLink(...)]` (and the email OTP, 2FA, passkey, API key and organization plugins) now create their tables, matching the config-key form.
  - core: new `createAdapterGuard` and `isProtectedAdapterPath` exports used by every adapter.
  - create-theauth-app: templates pin `@glinr/*` packages to the versions in this release instead of stale ranges, list `sql.js` (the driver behind `provider: "sqlite"`) and `zod`, and the hono-mcp template protects its management routes with an `ADMIN_API_KEY`. The next-saas catch-all route now passes the TheAuth instance to the adapter.

- 4e37e17: Add an opt-in tamper-evident audit trail. `audit: { tamperEvident: true, hmacKey }` links each audit row to the previous one with a SHA-256 or HMAC hash, one chain per agent. New `theauth.audit.verifyAuditChain`, `replayAgent` and `exportAudit` (JSONL plus a signed manifest), a `verifyAuditExport` helper, and `theauth audit verify` / `theauth audit replay` in the CLI. `theauth_audit_logs` gains nullable `chain_seq`, `prev_hash` and `hash` columns and a unique index on `(agent_id, chain_seq)`; `createTables` adds them to existing databases and old rows are left alone. Nothing changes unless you turn it on.
- 4e37e17: Add opt-in DPoP (RFC 9449) and a `requireMcpAuth` resource wrapper for MCP.

  - New `dpop` option on the MCP config. The token endpoint verifies proofs, issues `cnf.jkt`-bound tokens with `token_type: "DPoP"`, supports server nonces (`use_dpop_nonce`) and keeps a `jti` replay cache on `SecondaryStorage`. Refresh tokens stay bound to the original key. Metadata advertises `dpop_signing_alg_values_supported`.
  - New `requireMcpAuth(ctx, handler, options)` and `mcp.requireMcpAuth(...)`: verifies Bearer or DPoP tokens, audience and scopes, returns RFC 6750, RFC 9449 and RFC 9728 challenges, and passes the handler a principal (user, agent, delegation chain).
  - Security: a DPoP-bound token is now rejected when presented as a bearer token, including through `validateToken`, `middleware`, `withMcpAuth` and `requireScopes`.
  - `McpAccessToken.tokenType` and `McpTokenResponse.token_type` widen to `"Bearer" | "DPoP"`. Persist the new `dpopJkt` field in custom token stores.
  - Hono and Express adapters forward the `DPoP-Nonce` header from the token endpoint.

- 4e37e17: Edge case hardening and opt-in session features.

  - Security: single-use credentials (magic links, email OTP attempts and codes, one-time tokens, OAuth state, SIWE nonces) are claimed atomically, so concurrent requests cannot redeem the same one twice.
  - Security: the OAuth plugin links a provider login to an existing account by email only when the provider and the local account are both verified. Otherwise it returns 409. `linkAccount` refuses to move a provider account to a different user. New accounts store `emailVerified` from the provider instead of always true.
  - Security: `withRateLimit` and the OAuth proxy use the trusted proxy rules and ignore `x-forwarded-for` and `x-real-ip` by default. Behind a proxy, set `trustedProxy`.
  - Emails are normalized in one place across all email flows.
  - Express, NestJS and Nuxt adapters send each `Set-Cookie` as its own header. Express and NestJS plugin routes honor the mount prefix. Astro, Nuxt and SvelteKit dispatchers now serve plugin endpoints.
  - New and opt-in: session cookie cache, refresh token `reuseGracePeriod`, `allowedHosts` per-request base URL, `createStatelessSessions`, OIDC back-channel and RP-initiated logout helpers, shared SIWE nonce `storage`.

- 4e37e17: Feature-gap pass, all additive.

  - Unified OTP: `createOtpService` for email and SMS with purposes (sign-in, verify-email, reset-password, two-factor), resend cooldown, attempt lockout and constant-time checks. Senders: `emailOtpSender` (wraps any email provider), `twilioOtpSender`, `consoleOtpSender`. The email OTP and phone modules gain `resendCooldownSeconds`, and email OTP now compares hashes in constant time.
  - Email adapters: `ses` (SigV4 over fetch) and `postmark`. `resend`, `sendgrid` and `smtp` are now exported from `@glinr/theauth/auth`.
  - OAuth presets: Keycloak, Authentik, ZITADEL, OneLogin, Gitea, Patreon, Box, Yandex and WordPress.com. `genericOIDC` gains `mapProfile` and `userinfoAuthScheme`.
  - CLI: `theauth doctor` (with `--json`), `theauth secret` and `theauth completions`.

- 36f15a3: Harden the MCP authorization server and token families.

  Behavior changes: `resource` is now required at the authorize and token endpoints and in `approveConsent`; `withMcpAuth` and `validateAccessToken` require `expectedAudience` (the module methods use the new `config.resource`); client secrets and stored access and refresh tokens are SHA-256 digests (legacy plaintext rows are still accepted and upgraded); refresh rotation detects reuse and revokes the token family; unknown or widened scopes on refresh return `invalid_scope`; authorization responses include `iss` (RFC 9207); `jwks_uri` is only advertised with asymmetric signing; registration no longer fetches `client_uri`; delegation reads the parent's permissions from storage, clamps the child expiry to the inbound chain, and honors inbound `maxDepth`; `TokenFamilyStore.consumeToken` claims tokens atomically.

  New, opt in: ES256/EdDSA signing with `kid`, JWKS and key rotation; jti denylist; RFC 7009 revocation (`mcp.revoke`); Client ID Metadata Documents through an SSRF-safe fetcher.

- 4e37e17: Add an opt-in migration toolkit under `@glinr/theauth/migrate`. Importers for Auth0, Keycloak, Clerk, Better Auth, Auth.js and generic CSV or JSON feed one `importUsers` call with a dry run, idempotent re-runs and conflict policies. Lazy password migration verifies PBKDF2, scrypt and (with a verifier you pass) bcrypt or argon2 hashes on first login, then rehashes. `externalIssuers` accepts tokens from an existing OIDC provider with issuer, audience and algorithm pinning and a rotating JWKS cache, with optional just in time provisioning. A sticky percentage and cohort rollout (`percent: 0` is the rollback switch), a login onboarding hook that falls back to the incumbent on any failure, a shadow mode that never enforces, and a counts-only progress report. `theauth migrate plan | import | verify | status` replaces the old placeholder message. Nothing changes unless you call it.
- 4e37e17: OTP over HTTP, all opt-in. `otpRoutes` plugin adds `POST /auth/code/send` and `/auth/code/verify` (rate limited, enumeration safe). `twoFactor({ otp })` adds email or SMS codes as a second method, and `passwordReset.otp` adds `requestResetOtp` and `resetPasswordWithOtp` plus matching routes. Fix: the Facebook preset now maps the Graph API `id` to the profile id, so sign-in no longer fails with a missing `sub` error.
- 4e37e17: Outbound token vault. New `tokenVault()` plugin and `createTokenVault()` store third-party OAuth connections per user, encrypted with AES-256-GCM (key ids for rotation), and hand agents short-lived access tokens via `vault.getAccessToken({ agentId, userId, provider, scopes })`.

  - Each read checks the agent's `vault:<provider>` `use` permission (own or delegated), the user's consent for those scopes, and the connection's scopes. Scopes can only narrow. Every read is written to the audit log.
  - Refreshes are single flight (in process and through `secondaryStorage`, new `tokenVault` feature key).
  - Connect flow endpoints under `/auth/vault/*` use PKCE S256, single-use state and bind the callback to the signed-in user.
  - `theauth.delegation.revoke()` now also revokes vault consents tied to that chain when the plugin is installed.
  - Additive: new `theauth_vault_connections` and `theauth_vault_consents` tables, created only when the plugin is present.

- 4e37e17: Add a permission simulator. `createSimulator()` answers "what would this agent be allowed to do?" with a decision (`allow`, `deny`, `needs_approval`), reasons and a step by step trace, without writing audit rows or touching rate and budget state. It supports what-if overrides (extra permissions, other delegation chains, a budget cost), `simulateMany` for agent by action matrices, and `effectivePermissions`. The opt-in `simulator()` plugin mounts the admin-only `POST /agents/:id/simulate`, and the CLI gains `theauth simulate` and `theauth permissions`. Resource matching and constraint evaluation moved into shared helpers in `policy/abac.ts` so `authorize()` and the simulator run the same code; `authorize()` behavior is unchanged.
- 20aafa0: Pluggable secondary storage, hardened device auth, CLI login, agent registration tokens.

  - New `secondaryStorage` config with memory, database, Cloudflare KV, Redis-compatible and custom adapters, plus per-feature overrides. `kvStore`, `KVStore` and `RateLimitStore` keep working.
  - Security: `rateLimit()` no longer trusts `x-forwarded-for` by default. Set `trustedProxyCount` or `trustedHeader`. Behind a proxy without either, all clients share one bucket.
  - Security: device authorization takes the approving user from the authenticated session, never from the request body. The approval endpoint rejects cross-origin and non-JSON requests.
  - Device codes are stored hashed, user code guessing is limited per user, `slow_down` persists, and a granted code can be exchanged once. The token endpoint returns an `access_token` when a session manager or `issueToken` is configured.
  - `rateLimit()` now covers `/mcp/token`, `/mcp/register` and the device endpoints, with an optional per `client_id` key. `theauth.plugins.runRequestHooks()` is new, and `plugins.handleRequest` now runs `onRequest` hooks (they were collected but never invoked).
  - CLI: `theauth login`, `logout`, `whoami` and an exported `loginWithDeviceFlow` helper.
  - New `agentRegistration()` plugin: one-time, scoped, expiring tokens that let a headless agent register itself.

## 0.6.0

### Minor Changes

- 0fa5b1e: Remove the legacy KavachOS naming. The deprecated `Kavach*` and `createKavach` exports are gone: use `TheAuth*` and `createTheAuth`. Environment variables are now `THEAUTH_*`, webhook headers `X-TheAuth-*`, cookies and the default API route use `theauth`, and database tables are `theauth_*` (existing `kavach_*` tables are renamed in place by `createTables`, no data is lost). `Auth*` aliases remain deprecated.
- 9861742: Harden the SCIM 2.0 server. List endpoints now accept the full RFC 7644 filter grammar through a real parser, with operators eq, ne, co, sw, ew, gt, ge, lt, le and pr, the and, or and not combinators, parentheses and value path selectors, plus sortBy and sortOrder. PATCH supports path expressions with value filters such as emails[type eq "work"].value, rejects changes to immutable attributes and caps a request at 1000 operations. A new opt in Me endpoint resolves the caller through a resolveSelf callback, and the Bulk endpoint returns a spec compliant 501. Every successful provisioning write can now be recorded in the audit log by passing audit with an agent id. The Enterprise User extension is supported and advertised in the Schemas endpoint, and the repo gains an Okta example and a compatibility table.

### Patch Changes

- 960fe89: Delegation requests whose permissions are not a subset of the parent's now return HTTP 400 with error code `DELEGATION_PERMISSION_SUBSET` instead of a 500. Core throws a typed `DelegationError` (codes `DELEGATION_PERMISSION_SUBSET` and `DELEGATION_DEPTH_EXCEEDED`) and every REST adapter maps it to a 400 using that code.
- dfd31f9: Fix `ipAllowlist` denying every REST call. The permission engine now resolves the client IP from the request context first (what the framework adapters pass), then `request.ip`, so the allowlist and audit log agree.
- 5e53bdb: Fix plugin endpoint rate limit windows in the anonymous, device, SIWE, and OAuth proxy plugins. They declared `rateLimit.window` in milliseconds while the plugin router reads it as seconds, so a 60_000 window lasted about 16 hours. The window is now in seconds, and the `PluginEndpoint` type documents the unit.

## 0.5.0

### Minor Changes

- TheAuth is now the canonical naming across the SDK (`TheAuthClient`,
  `TheAuthProvider`, `TheAuthError`, `createTheAuth`, and per-adapter
  equivalents like `theAuthExpress`/`theAuthHono`). This resolves a
  three-way naming collision: an earlier pass renamed `Kavach*` to `Auth*`,
  this pass supersedes that with `TheAuth*` as canonical.

  Non-breaking. Both `Auth*` and `Kavach*` names remain as deprecated
  aliases pointing at the same implementation and will keep working until
  a future major version. No behavior changed, only naming.

  Also fixes two adapters (`express`, `hono`) that were missed by the
  earlier `Auth*` rename entirely and still only exported `kavach`-prefixed
  names.

## 0.4.2

### Patch Changes

- fix: re-export the 10 new OAuth provider factories from `@glinr/theauth/auth`

  The wave that added Notion, Spotify, Discord, Slack, Twitch, Reddit, Figma, Dropbox, Zoom, and Atlassian updated the OAuth `providers/index.ts` barrel but left the top-level `auth/index.ts` pointing at the old 9-provider list. Consumers could not import the new factories or their `DEFAULT_*_SCOPES` constants from `@glinr/theauth/auth`. Replaced the explicit list with `export *` so new providers picked up automatically in future releases too.

## 0.4.1

### Patch Changes

- fix: expose the `@glinr/theauth/standards` subpath

  The standards module shipped in 0.4.0 but was missing from `tsup.config.ts` entries and the `exports` field in `package.json`. Consumers can now `import { AGENTIC_JWT_CLAIMS } from "@glinr/theauth/standards"` as the docs describe.

## 0.4.0

### Minor Changes

- feat: v3 wave

  - Agentic JWT claim constants (`AGENTIC_JWT_CLAIMS`) from `draft-goswami-agentic-jwt-00` and `draft-liu-agent-operation-authorization-01`, behind a new `emitAgenticJwtClaims` config flag. Populates `agent_id`, `agent_type`, and `trust_tier` on issued tokens when on. Off by default.
  - Ten OAuth providers (Notion, Spotify, Discord, Slack, Twitch, Reddit, Figma, Dropbox, Zoom, Atlassian) promoted to first-class named exports with typed factories, `DEFAULT_X_SCOPES` constants, and profile normalisers.
  - `exportAuditAsVC` in `@glinr/theauth/vc` for compliance audit exports as W3C Verifiable Credentials (`ldp_vc` or `jwt_vc`, individual or Verifiable Presentation).
  - Initial `@glinr/create-theauth-app` scaffolder on npm with a Next.js App Router template.

## 0.3.0

### Minor Changes

- feat: add cookieAuth adapter and external auth mode

  - `cookieAuth()` adapter: validates JWT from httpOnly cookies (for Go/Python/etc backends)
  - `KavachProvider` external mode: delegate auth to any external API
  - Feature-gated table creation: only creates tables for features you enable

## 0.1.0

### Minor Changes

- 94804ec: Launch release: promote core and primary client-facing packages to the 0.1 line.

  Highlights:

  - Stabilize package exports and build artifacts for launch.
  - Ship improved CLI version handling and launch docs.
  - Keep adapters/plugins/dashboard on existing release tracks for a separate coordinated versioning pass.
