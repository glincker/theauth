# theauth

## 2.0.1

### Patch Changes

- d1f20cc: `session.list()` now uses the injected clock, like `validate`, so expiry is consistent when a clock is provided. Adds `tsx` as a dev dependency so the audit chain vector test runs in CI.

## 2.0.0

### Major Changes

- a561306: Security fix: `authorize(agentId)` now denies an agent whose `expiresAt` has passed, with code `agent_expired` and a denied audit row. Before, it checked only the stored `status`, so an elapsed agent kept passing until its status was flipped. Marked major because an agent that passed before can now fail. `authorizeByToken()`, `agent.validateToken()` and `policy.evaluate()` were already correct. See `docs/upgrading-to-2.mdx`.
- 551240a: Approvals are a first-class flow. A failed `approvalId` spend in `authorize()`, `authorizeByToken()` and `policy.evaluate()` now returns a distinct code: `approval_not_found`, `approval_pending`, `approval_denied`, `approval_expired`, `approval_already_used`, `approval_mismatch` or `approval_arguments_mismatch`. The generic `approval_invalid` code is no longer returned (breaking), and the `APPROVAL_NOT_APPROVED` reason is split into `APPROVAL_PENDING` and `APPROVAL_DENIED`. `approval.approve()` and `approval.deny()` throw for an expired request and mark it `expired`, and `approval.listPending(ownerId)` leaves out expired requests. Added `approval.decide(id, { decision, decidedBy })`, an `approval.expire` audit row, decision events with `source: "approval"` (codes `approval_pending`, `approval_granted`, `approval_denied`, `approval_expired`), and an `approval.pending` webhook event that carries a hash of the arguments, not the arguments. New exports: `decisionCodeOfApproval`, `isApprovalDenial`, `ApprovalDeps`, `DecideInput`. See `docs/upgrading-to-2.mdx`.
- a561306: Audit API v2: explicit order, cursor paging and one event vocabulary.

  - `audit.query()` takes `order: "asc" | "desc"`. The default stays `"desc"` (newest first), so existing calls return the same order. New filters: `events`, `resource` (exact, or prefix with a trailing `*`) and `cursor`. `actions` is now applied in the query, before `limit`, instead of after it.
  - New `audit.page(filter)` returns `{ entries, nextCursor }`. The cursor is opaque and keyed on `recorded_at_ms` plus `id`, so pages are stable when rows share a millisecond or arrive between requests. `offset` is deprecated and ignored when a cursor is set.
  - New nullable `event` column (migration `0005`, index `(agent_id, event, recorded_at_ms)`) and `AuditEntry.event`. `event` says what happened (`authorize`, `policy.evaluate`, `delegation.create`, ...), `action` keeps the domain verb. Migration `0005` backfills `event` from the old action for rows it can classify and leaves the rest NULL. `event` is not part of the audit hash, like `decision_code` and `recorded_at_ms`: hash inputs are unchanged, existing chains keep verifying.
  - `GET /audit` still answers a bare array. Add `paged=true` or `cursor` for `{ entries, nextCursor }`; it also accepts `order`, `events` and `resource`. An invalid cursor answers 400.
  - The `query_audit` MCP tool gains `events`, `resource`, `order` and `cursor`, drops `offset`, and now returns `{ returned, nextCursor, entries }`.

  Upgrade notes:

  - `AuditEntry` has a new `event` field (`null` when unknown). Code that builds `AuditEntry` values by hand must set it.
  - Delegation rows now carry `action: "delegate"` with `event: "delegation.create"` or `"delegation.revoke"`. Rows written before the upgrade keep `action: "delegation.create"` or `"delegation.revoke"` (the column is hashed, so it is not rewritten); filter on `event` to see both. Anything that matched `action === "delegation.create"` must match `event` instead.
  - With `skipMigrations: true`, apply `0005` by hand (`theauth db sql --from 0005`) before deploying.

- a561306: Password lockout, fail closed options and a return URL allow list.

  Visible default change (the reason for the major bump): username sign-in now locks repeated failures. 10 failed attempts for one username inside 15 minutes lock it for 15 minutes (doubling per repeat, capped at 1 hour), and 3 failures from one IP for one username start a growing delay for that IP. A locked sign-in answers `429` with `Retry-After` and code `SIGN_IN_LOCKED`, and `signIn` throws `LoginLockedError`. Unknown usernames lock identically, so responses do not reveal which accounts exist. Set `username: { lockout: false }` or `THEAUTH_LOGIN_LOCKOUT_DISABLED=true` to keep the old behavior, and tune with `username.lockout` or the `THEAUTH_LOGIN_*` variables. New: `theauth.username.unlockAccount(name)`, the `onLockout` hook and `username.trustedProxy`.

  Redirects: `createRedirectChain` now refuses off-site targets. A chain path that is protocol-relative, uses backslashes or control characters, or is an encoded variant of those now comes back as `defaultPath`. New: `redirects.sanitize()`, `allowedOrigins`, and `resolveRedirectTarget` / `safeRedirectTarget` in `@glinr/theauth/redirect`. OAuth modules accept `allowedRedirectUris` (off unless set).

  Fail closed (all additive, default stays fail open): `rateLimit.failClosed` for the adapters and handler, `failClosed` on the `rateLimit()` plugin, and `hibp.failClosed` answer `503` or `HibpApiError` when the backing store or API errors. While a limiter fails open it logs a startup warning through the configured logger.

- a561306: Cookies are now `Secure` by default on every runtime, and password hashing is stronger.

  Breaking: the `Secure` default no longer reads `NODE_ENV`. It was off whenever `NODE_ENV` was unset (Cloudflare Workers, Deno, Bun). It is now on unless you pass `secure: false`, or pass a `request` for plain `http://localhost`, `127.0.0.1` or `[::1]`, where it turns off for local development. https URLs and trusted proxy `x-forwarded-proto` headers (`trustProxy`) keep it on. Chrome and Firefox accept `Secure` cookies on localhost; for plain-HTTP setups elsewhere pass `cookieOptions.secure: false`.

  Cookie serialization is centralized in `serializeCookie` (session manager, cookie cache, refresh, plugins and the redirect chain all use it). New `resolveCookieSecure(request, { trustProxy })`. `__Host-` and `__Secure-` prefixes are validated and invalid combinations throw, as do `Partitioned` or `SameSite=None` without `Secure`.

  Password hashing: PBKDF2-SHA256 now defaults to 600000 iterations (was 100000), set with `pbkdf2Iterations` or `THEAUTH_PBKDF2_ITERATIONS`. The stored format `pbkdf2:<iterations>:<salt>:<hash>` is unchanged, old hashes verify with their own iterations and are upgraded on successful sign-in. Unknown usernames now spend a hash to avoid a timing oracle. Expect about 100 ms per hash; lower the value on CPU-limited Workers plans.

- a561306: Add `@glinr/theauth/http`: one web-standard HTTP handler for every theAuth route, so framework adapters no longer carry their own copy.

  New exports: `createTheAuthHandler(auth, options)` returning `(request: Request) => Promise<Response>`, `listRoutes(options)` (the route table, `RouteSpec[]`), `requireAgent(auth, request, { action, resource, clientIp? })`, and the Node bridge `toWebRequest` and `sendWebResponse`. Options extend the existing adapter security options (`authenticate`, `allowUnauthenticated`, `trustedProxy`, `rateLimit`, `trustedOrigins`, `csrf`) with `mcp`, `basePath`, `routes` and `maxBodyBytes` (default 1 MiB, 413 above it).

  Behavior changes (breaking):

  - `POST /mcp/revoke` (RFC 7009) and `GET /mcp/jwks` are now served. Previously the metadata advertised both and no adapter served them.
  - `/.well-known/oauth-authorization-server` and `/.well-known/oauth-protected-resource` list only the MCP endpoints that are mounted (`routes.mcp` accepts `{ register, authorize, token, revoke, jwks }` booleans). New helpers in `@glinr/theauth/mcp`: `applyMountedToServerMetadata`, `applyMountedToResourceMetadata`, `ALL_MCP_ROUTES`.
  - New admin route `POST /explain` wrapping `theauth.explain`.
  - Status codes are now identical across frameworks: `POST /authorize/token` answers 401 for `invalid_token`, `agent_not_found`, `agent_revoked`, `agent_expired` and 403 for every other denial (it used to answer 403 for both). A known path with the wrong method answers 405 with `Allow`. Unexpected errors answer a fixed 500 message instead of echoing the exception text. `GET /audit` accepts `result=escalated`.
  - `requireAgent` branches on the decision code, never on reason strings. Denial bodies are `{ error: { code, message } }` where `code` is the decision code (lowercase, for example `no_permission`), not `UNAUTHORIZED` or `FORBIDDEN`.

  Adapter authors: replace each adapter's dispatcher with `createTheAuthHandler` and delete the per-adapter `dispatch.ts`. Option names are the unified ones above.

- a561306: Security fix: token vault use and policy-shrink grants now honor delegator liveness. A downstream agent can no longer use a vault credential through a consent whose delegation chain includes a revoked or expired agent, and `loadGrants`/`analyzeUsage` no longer count grants from dead links. Also, an active delegator whose inbound links are all dead keeps the onward links that grant only permissions it holds directly (before, they died with the inbound chain). Marked major because vault access that succeeded before can now be refused. See `docs/upgrading-to-2.mdx`.
- a561306: Security fix: a delegation link now lends permissions only while its delegator agent is live. Before, `getDelegatedPermissions`, `resolveLineage` and `resolveHookChain` checked the link but never the status or `expiresAt` of the delegating agent, so a revoked or expired intermediate agent kept lending to agents below it and still appeared as valid in the `beforeAuthorize` chain. `authorize()`, `authorizeByToken()`, `policy.evaluate()`, `explain()`, the simulator and the live MCP delegation check now agree. Marked major because chains that passed before can now fail. See `docs/upgrading-to-2.mdx`.
- 2d27ad0: Close three 2.0 blocker gaps. The JWT session module and the stateless session manager now refuse banned users with `USER_BANNED` (stateless takes a `db` or an `isBanned` callback, and with either one a ban also ends sessions already issued). `org.handleRequest` and `apiKeys.handleRequest` fail closed: they answer 401 without an authenticate resolver, bind ids to the signed-in user, and check org membership and role. Trusted server code can opt out with `trustedServerUse: true`. The MCP authorization code grant refuses a client an admin bound to another user's agent, with `ACCESS_DENIED` at authorize and `INVALID_GRANT` at token, both carrying `details.decisionCode` `owner_mismatch`. See the upgrade notes in `docs/upgrading-to-2.mdx`.
- a561306: `beforeAuthorize` now runs after the agent is resolved and active, with a richer context (`agent`, `delegation` chain from the root human, `source`, `context`, `dryRun`, `signal`), and for `authorizeByToken()` and `policy.evaluate()` (agent subjects) as well as `authorize()`. It no longer runs for unknown agent ids, invalid tokens, or revoked or expired agents. `authorizeByToken()` now honors delegated permissions and fires `afterAuthorize` and `onViolation` like `authorize()`. Hooks run under a timeout and fail closed: a `beforeAuthorize` timeout, throw or malformed verdict denies with code `hook_timeout` or `hook_error`, and a `beforeAgentCreate` timeout or throw makes `agent.create()` throw. Configure with `hookSafety` or `THEAUTH_HOOK_TIMEOUT_MS`, `THEAUTH_HOOK_ON_TIMEOUT`, `THEAUTH_HOOK_ON_ERROR`; `onError: "throw"` restores the old propagate behavior. Hook verdicts may also be `{ decision: "allow" | "deny" | "escalate" }`. See the upgrade notes in `docs/upgrading-to-2.mdx`.
- a561306: Core: `toWebRequest` now records the socket remote address out of band, exposed as `peerAddressOf(request)`. Without `trustedProxy` the handler, rate limiter and `requireAgent` use that peer address as the client IP, so per-IP limits and `ipAllowlist` work on direct Express, Fastify and NestJS deployments. Forwarded headers are still only believed when `trustedProxy` is set. `requireAgent` accepts `trustedProxy`.

  Breaking: `GET /audit/export?userId=<other user>` by a caller limited to their own resources is now `403` with `{ error: { code, message } }` instead of silently returning the caller's rows.

  Fastify: the handler is built once at registration, so `allowUnauthenticated` warns once. `requireScope` matches `ipAllowlist` against the socket peer by default. The fail-closed check without an authenticator now surfaces when the plugin registers instead of at `theAuthFastify(...)`.

- a561306: Security fixes from the HTTP handler review. Some of these fix bugs that are in published releases (1.2.0 and earlier), others fix unreleased 2.0 work only.

  Also affects published versions (1.2.0 and earlier):

  - `theauth.username.handleRequest`: `/auth/username/change-username` and `/auth/username/change-password` now need a signed-in session (Bearer token or session cookie) and act on that session's user. A `userId` in the body is ignored, and with no session the answer is 401. Both also require a JSON content type, so a cross-site form post cannot ride the cookie. Breaking: clients that sent `userId` without a session must send the session instead.
  - `changePassword(userId, current, newPassword, context?)` now runs under the login lockout (keyed by user id, plus the per-IP backoff when `context.request` is passed), spends the same hashing time for an unknown account, and throws the same `Current password is incorrect` error for an unknown account and a wrong password.
  - `passkey()` plugin: `/auth/passkey/register/options` and `/auth/passkey/register/verify` always register for the signed-in user. A body `userId` used to win over the session, so any signed-in user could bind a passkey to another account.
  - `additionalFields()` plugin: `GET` and `PUT /auth/users/fields` act on the signed-in user. A different `userId` in the query or body is refused with 403.
  - `theauth.totp.handleRequest`, `theauth.passkey.handleRequest` (registration and credential routes) and `theauth.emailVerification.handleRequest` (`/auth/verify-email/send`) now take the user from the auth adapter or the session, never the body or query, and answer 401 without one. `createTotpModule`, `createPasskeyModule` and `createEmailVerificationModule` take an optional `{ resolveUser }` for standalone use; without it those routes answer 401. Breaking for callers that relied on a body `userId`.
  - `rateLimit()` plugin: `signIn`, `signUp` and `passwordReset` now map to the routes core ships (`/auth/username/sign-in`, `/auth/username/sign-up`, `/auth/forgot-password`, `/auth/reset-password` and their OTP variants, among others). Before, they matched no shipped route, so those limits never applied. New `codeSend` and `codeVerify` keys cover magic link, email OTP, phone, verify-email and second factor code routes. Every credential route now has a built-in limit when its key is not configured; `false` turns a key off. Paths are normalized before matching and keying (repeated and trailing slashes, case, percent encoding), so another spelling of a path no longer gets a fresh counter. Breaking: `default` no longer applies to credential routes, which now get their specific or built-in limit.

  Unreleased 2.0 work only (the HTTP management router was never published):

  - `PATCH /agents/:id` and `theauth.agent.update` now run the `beforeAgentCreate` policy on the agent as it would look after the update, with the same fail closed handling as create. Updating a compliant agent to a wildcard grant is refused when the policy refuses wildcards. A policy refusal on create or update is now a 403 instead of an opaque 500.
  - `POST /delegations` requires the caller to own both `fromAgent` and `toAgent` (owner only), and `theauth.delegate` refuses a target agent that does not exist or is not active.

- a561306: Security hardening from the HTTP handler review, part B.

  Fixes that also affect PUBLISHED versions (verified against origin/main):

  - nextjs-auth: the refresh cookie now uses the `__Host-` prefix (`__Host-{prefix}-refresh-token`, Secure, Path=/, no Domain) whenever `secure` is on, not only in production. Before, a sibling subdomain could set the unprefixed cookie and sign a visitor in as the attacker (login CSRF). `secure: false` (plain http localhost development) is the only way back to the unprefixed name. Existing refresh cookies under the old name are ignored and cleared, so each user signs in once more after the upgrade.
  - Adapter admission (`adapter-admit`): with an unknown client IP, requests no longer share one global `unknown` bucket or get a bucket per raw `Cookie` or `Authorization` value (a random cookie bypassed the limit). They now fall into three fixed buckets (anonymous, cookie, authorization) and a one-time warning is logged. Limits are only per client with `trustedProxy` or `rateLimit.key`; see `docs/rate-limiting.mdx`.
  - Redirect chain: `createRedirectChain` kept `currentState` in a shared closure, so one user's origin path and query (for example a share token) could land in another user's cookie. State now comes only from the request. BREAKING: `push(path, options)` is now `push(request, path, options)`, and it reads the chain from that request's cookie.

  Fixes in unreleased 2.0 work only (these code paths are not on main):

  - HTTP handler: `readJsonBody`, `/mcp/register` and `/mcp/token` enforce `maxBodyBytes` while streaming. A Content-Length over the cap is refused up front and the reader is cancelled once the running total passes it (413). Before, a chunked body was buffered in full first.
  - Login lockout: `check()` now reserves an attempt slot with an atomic increment before the password is verified, and a correct password refunds it. 200 parallel guesses with `maxFailures: 10` now perform about 10 password checks instead of 200. A lock and its escalation strike are set once per burst.
  - MCP routes return a fixed `server_error` description on 500 (register, authorize, token, jwks). The original error goes to the configured logger.

  Express and NestJS adapters (also on main): the per-mount handler cache is keyed by the lowercased mount and capped at 32 mounts, so request-chosen spellings of `req.baseUrl` no longer build a handler (guard, admission, compiled routes) each.

- a561306: The core HTTP handler now sets `Cache-Control: no-store` and `Pragma: no-cache` on every response by default (a route's own value wins; `GET /mcp/jwks` stays public), and adds opt-in `securityHeaders` and `cors` options.

  Visible behavior changes, hence major:

  - The MCP routes no longer send `Access-Control-Allow-Origin: *`, and the handler no longer answers every `OPTIONS` on `/mcp/*` and `/.well-known/*` with wildcard CORS. Browser MCP clients need `cors: { origins: [...] }` (or `origins: ["*"]` for the public discovery documents only). `token`, `introspect` and `revoke` are never CORS enabled unless named under `cors.groups`.
  - `OPTIONS` on a served path answers 204 with `Allow`, before authentication.
  - Discovery documents and other responses that had no `Cache-Control` now carry `no-store`.
  - `MCP_CORS_HEADERS` and `mcpPreflight` were internal and are removed.

  New: `securityHeaders` option (nosniff, no-referrer, CORP, HSTS only over https or a trusted proxy, frame and CSP on HTML), the `securityHeaders()` and `isSecureRequest()` helpers from `@glinr/theauth/http`, and a startup warning through the observability logger for `allowUnauthenticated` and permissive CORS.

- a561306: Client ID Metadata Documents (CIMD) are stricter, and some configurations that worked before now fail at startup.

  - Turning on `clientIdMetadataDocuments.enabled` without a `consentPage` now throws when the MCP module is created. Before, any host could publish a client document and get an authorization code without the user approving anything. The authorize path also refuses a CIMD client with `CONSENT_REQUIRED` if no consent page is set.
  - A `client_id` must be a canonical https URL on port 443 with a path. Hostnames that are IP literals, single labels, local or internal suffixes, or wildcard DNS services are refused before any fetch. A configurable `allowedHosts` and `deniedHosts` apply on top.
  - The fetcher accepts only an exact 200 JSON response, never follows redirects, caps the body size and enforces one deadline across DNS, headers and body. A bounded limiter caps concurrent DNS lookups. Errors returned to callers are generic, and detail goes to `onEvent` and the logger.
  - On runtimes without `node:dns` the `auto` resolver cannot check addresses: with no `allowedHosts` CIMD now fails closed, and with `allowedHosts` it warns once. `createDohResolver()` is a fetch-only resolver for edge runtimes. DNS rebinding cannot be fully ruled out in any mode, and only `allowedHosts` closes it. See `docs/mcp-client-id-metadata.mdx`.
  - Fetched documents are validated strictly (the document repeats its own client_id, no shared secrets, no agent fields, exact redirect URIs, size limits). A refresh never undoes an admin's `disabled` state, `agentId` or block, and a bound client whose redirect URIs or auth method change is disabled. Freshness comes from the stored expiry, so isolates agree.
  - New admin API `mcp.cimd` (block, unblock, list, refresh) and `mcp.describeClient()` for the consent page, with warnings such as a localhost or http redirect. A block on a URL revokes the client's tokens and adds their jtis to the denylist; a block on a host stops its clients and deletes tokens when the store can list them. Only an admin can bind a CIMD client to an agent.
  - Per-host fetch limit (30 a minute), a cap of 1000 unconsented CIMD client rows with a daily sweep, case-sensitive client id matching, bounded JWKS and negative caches, and `enabled: false` no longer serves stored CIMD rows. Migration `0008` adds the snapshot columns and the `theauth_mcp_client_blocks` table.
  - `registration: { enabled: false }` turns off dynamic client registration: the route returns 404 and `registration_endpoint` leaves the metadata.

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

- a561306: MCP access tokens are now bound to the delegation they came from, and revoking that delegation stops them.

  - Tokens minted by RFC 8693 exchange keep the `act` chain and gain a signed `theauth_dlg` claim (`{ v: 1, agt, lnk }`) naming the agents and delegation records behind them. A token never outlives the earliest of its delegation links, its agents and the token it was exchanged from. Exchanged tokens do not get refresh tokens. Tokens for a client bound to an agent carry the agent in the claim too.
  - Validation has three freshness modes: `live` (checks the shared denylist and the delegation chain on every request), `cached` (a bounded cache, `maxStalenessMs` defaults to 5 seconds) and `offline` (trusts the signed claim until `exp`). The default is `live` when a database is configured and `offline` otherwise. Signature, audience, issuer, expiry and DPoP are always checked before the claim is read, and a store error fails closed with a 503 from `requireMcpAuth`.
  - New shared denylist table `theauth_mcp_revocations` (migration `0007`), which also adds the missing `delegation_chains` indexes. Revoking a delegation (including its cascade), revoking an agent, signing a user out everywhere and `/mcp/revoke` all write to it, so the next request fails on every instance that shares the database. CAEP `session-revoked` events are emitted when the signals module is configured.
  - New `POST /mcp/introspect` (RFC 7662). It always checks live state. Only the token's own client or a configured resource server gets the claims or the reason a token is inactive; everyone else gets `{"active":false}`. `McpAuthModule.introspect` is now required.
  - `McpBindingRefused` is returned as `invalid_grant` on every grant type, the binding is checked before an authorization code is consumed when the client is bound to an agent, and `expires_in` reports the capped lifetime.
  - `jtiDenylist` now defaults to the database store when a database exists.

  Limits that stay true: a resource server that validates the JWT offline or caches introspection sees a revocation at token expiry or when its cache expires; a request already past validation finishes; tokens minted before the upgrade carry no binding and age out within the access token lifetime; the HS256 shared secret can forge the claim, so use RS256 or ES256 for resource servers you do not fully trust; nothing pushes a revocation when an agent simply expires, expiry is enforced at check time. See `docs/mcp-revocation.mdx`.

- f197327: `generateOpenAPISpec` now builds the document from the handler's route table and the core result shapes, and the result is checked in as `sdks/openapi.json` with a test that fails on drift.

  Upgrade notes:

  - `servers[0].url` is `baseUrl` plus the new `basePath` option (default `/api/theauth`). Pass the origin as `baseUrl`.
  - Paths now match the served routes. `AuthorizeResult` has a required `code`, and explain, delegation chain fields, approvals and `/mcp/introspect` are described.
  - `POST /authorize` and `POST /authorize/token` accept `approvalId`, which was dropped before.
  - New options: `handler` (leave out routes the handler does not serve) and `adminApi`.

- a561306: Security fix for SAML SSO. Upgrade if you use `sso.saml`. Every published release with SAML support is affected, including 1.2.0.

  What was wrong:

  - Signature checking could be bypassed. When the element named by the signature `Reference` could not be found, or `DigestValue` or `DigestMethod` was missing, the digest check was skipped and only `SignedInfo` was verified. The user identity was then read from the first matching element anywhere in the document, not from the signed element.
  - The digest and `SignedInfo` were hashed from raw text with no canonicalization, unknown algorithms fell back to SHA-256, and SHA-1 was always accepted.
  - `cert` was imported as a bare public key. A real X.509 certificate is not one, so with genuine IdP certificates verification may never have succeeded.
  - `wantAuthnResponseSigned: false` turned signature checking off completely.
  - `InResponseTo` was never enforced through the built-in routes, there was no assertion replay cache, and the IdP `Issuer` was never checked against a configured value.

  What changed:

  - New verifier: one `Reference` to a same-document `#id` that must be the element holding the signature, duplicate ids rejected, exactly enveloped-signature plus exclusive c14n, exclusive c14n 1.0 on the parsed tree, allowlisted algorithms, constant time digest comparison. Claims are read only from the verified Assertion.
  - `cert` accepts an X.509 certificate (PEM or bare base64) or a public key PEM. RSA keys under 2048 bits are rejected.
  - New required provider option `idpEntityId`. Logins fail with `SAML_CONFIG_ERROR` until it is set.
  - `wantAuthnResponseSigned: false` is now a config error. The Response or the Assertion must be signed.
  - `allowLegacySha1` (default `false`) for IdPs that still sign with SHA-1. `allowIdpInitiated` (default `false`) for unsolicited responses. `clockSkewSeconds` is limited to 0 through 300.
  - `getSamlAuthUrl` stores the AuthnRequest id in secondary storage (feature `nonces`) and sends an opaque single-use `RelayState`. The ACS route passes it back, so `InResponseTo` is checked. Your own relay state is returned as `relayState` in the result. `handleSamlResponse` takes `{ relayState }` or `{ expectedRequestId }` as its third argument.
  - Assertion ids are kept in a replay cache until the assertion expires.
  - The XML parser rejects DOCTYPE, ENTITY, unknown entity references and duplicate attributes, enforces size, depth, attribute and element limits (`xmlLimits`), and rejects comments inside `NameID` and attribute values.
  - `SAMLRequest` was URL-encoded twice in the redirect URL. Fixed.

  Encrypted assertions and detached signatures are still not supported. See the SSO docs for the full list of checks and limits.

- a561306: Versioned schema migrations with a ledger. TheAuth now records every schema change in `theauth_schema_migrations` (`id`, `name`, `checksum`, `applied_at`), runs pending migrations at startup, and exposes the state as `auth.schema.status()`. `createTables()` is a thin call to the new runner. The 1.x tables are migration `0000` (`baseline`); the audit and policy columns are `0001` to `0003`. Ids `0004` to `0006` are reserved for upcoming work.

  New `theauth db status | up | sql [--dialect sqlite|postgres|mysql] [--from <id>] [--json]` in the CLI. New exports from `@glinr/theauth`: `getSchemaStatus`, `runSchemaMigrations`, `migrationSql`, `SCHEMA_MIGRATIONS`, `SchemaOutdatedError`, `SchemaChecksumError`.

  Upgrade notes:

  - **`database.skipMigrations: true` users must apply the ledger SQL.** The schema check now runs at startup: if migrations are pending, `createTheAuth` throws `SchemaOutdatedError` listing their ids instead of failing on the first write. Generate the SQL with `theauth db sql --dialect <yours>` (on a database that already has the 1.x tables use `--from 0002`, which also creates the ledger and stamps `0000` and `0001`), run it with your own tooling, then deploy. Each migration ends with an `INSERT` into the ledger, so it reads as applied. The old hand-run files `0001_*.sql` to `0003_*.sql` are replaced by generated files under `src/db/migrations/sql/<dialect>/`.
  - Databases without the ledger are adopted, not rebuilt: tables found at the 1.x shape are stamped as applied and only the missing migrations run. Existing rows are untouched.
  - An applied migration whose SQL no longer matches its ledger checksum stops startup with `SchemaChecksumError`.
  - `decision_code` and `recorded_at_ms` stay out of the audit hash, so existing chains keep verifying.
  - `src/db/schema.ts` is now a barrel over `src/db/schema/*.ts` and the DDL moved to `src/db/ddl/*.ts`. Public imports are unchanged.
  - Postgres and MySQL now have a dialect test suite (`packages/core/tests/dialect`, opt in with `THEAUTH_TEST_PG_URL` and `THEAUTH_TEST_MYSQL_URL`). See the Database setup and storage pages for what it covers.

- a561306: `provider: "sqlite"` now throws `THEAUTH_SQLITE_NOT_PERSISTENT` at startup when `url` is anything other than `:memory:` (or empty). That provider runs on sql.js, an in-memory engine that does not reliably write the database file, so a file URL looked like it worked and then lost the data on restart. The error tells you what to do: use `provider: "sqlite-native"` (better-sqlite3, `npm install better-sqlite3`) or Postgres for a database file, or pass `url: ":memory:"` for an ephemeral database. The old behavior of loading an existing file into sql.js is removed. Docs, READMEs and examples that passed a file URL now use `sqlite-native`.
- fe7e6c6: Step-up authentication (RFC 9470) and sender constrained agent tokens (RFC 7800, RFC 9449, RFC 8705). Sessions record how the user proved who they are (`session.auth` with `acr`, `amr` and `authTime`, and `sessions.recordAuth` for a step-up). Approvals take a rule (`approval.requireAcr`, `maxAuthAge`, `stepUp`, or `stepUp` on `request()`) and `approve` throws `StepUpRequiredError` unless the approver's assertion meets it; the admin API answers 401 with the `insufficient_user_authentication` challenge, and risk tiers can name the rule. The MCP server honors `acr_values` and `max_age` when given `resolveAuthContext`, signs `acr`, `amr` and `auth_time` into tokens, reports them from introspection, and `requireMcpAuth` and `requireScopes` can demand a login strength. Agent tokens can be bound with `cnf` (DPoP key or certificate thumbprint), checked on `POST /authorize/token`, `requireAgent` and inside `authorizeByToken`, with a replay cache, nonces, `POST /agents/introspect` and `agents.confirmation.required`. Marked major because `DecisionCode` gains `confirmation_required`, `confirmation_failed` and `approval_step_up_insufficient`, `SessionManager` gains `recordAuth`, and a `step_up` risk tier can now be satisfied by a strong enough approval. Migrations 0009 and 0011 add nullable columns. See `docs/step-up-auth.mdx`, `docs/dpop-agent-tokens.mdx` and `docs/upgrading-to-2.mdx`.
- a561306: Add typed decision codes. `authorize()`, `authorizeByToken()` and `policy.evaluate()` return a `code` from the closed set `DECISION_CODES`, and `onViolation` receives `code` next to `type`. `onViolation.type` is now derived from the code instead of substring matching on the reason text, so an agent named `pirate-bot` is no longer reported as `rate_limited`, and a `beforeAuthorize` block is always `permission_denied` with code `hook_denied`. `PolicyDecision.code` is a new required field. `classifyViolation` is deprecated. New exports: `DECISION_CODES`, `DecisionCode`, `DenialCode`, `isDecisionCode`, `violationTypeOf`. See the upgrade notes in `docs/upgrading-to-2.mdx`.

### Minor Changes

- be213ce: Add the `@glinr/theauth/integrations` subpath with dependency free helpers for agent frameworks. `guardAiSdkTools` wraps a Vercel AI SDK tool map and `guardFunctionTool` wraps an OpenAI Agents SDK style function tool. Each call runs `authorize` first, with an optional approval retry, and a refusal comes back as a structured `ToolDenial` carrying the decision code. `createHttpGuard` calls `POST /authorize/token` for Node orchestrators such as LangGraph.js. All helpers fail closed and use structural types, so no framework is imported at runtime. Docs: `integrations/vercel-ai-sdk`, `integrations/openai-agents-sdk`, `integrations/langgraph-crewai` (includes Python REST recipes for LangGraph and CrewAI).
- a561306: Agent tokens now start with `ta_` instead of `kv_` (a leftover of the old kavachOS name). The format is otherwise unchanged: `ta_` plus 43 base64url characters (32 random bytes), SHA-256 hashed at rest.

  Compatible migration: tokens already issued with `kv_` keep validating. Lookups are by token hash, so no stored data is rewritten and no database migration is needed. `agent.rotate` issues a `ta_` token for a legacy agent and retires the old one. A bearer string with neither prefix is now rejected before any database lookup.

  Added `AGENT_TOKEN_PREFIX`, `LEGACY_AGENT_TOKEN_PREFIXES`, `isAgentToken` and `agentTokenLookupPrefix` to `@glinr/theauth`. The MCP `inspect_token` tool recognizes both prefixes. If you match agent tokens by prefix in your own code (proxies, log scrubbers, secret scanners), accept both `ta_` and `kv_`. "Token format" in `docs/agents.mdx` has a scanning regex for GitHub secret scanning and gitleaks.

- 3953479: Self service API keys are capped to the caller. `POST /auth/api-keys` (the `apiKeys` plugin and the `apiKeys.handleRequest` module handler) refuses with 403 `permissions_not_grantable` when the key asks for a permission the signed in user does not hold. New `ApiKeyManagerConfig` fields: `grantablePermissions(userId)` returns the user's own permissions (`*` and `ns:*` patterns cover narrower ones) and `adminOverride(userId)` lifts the cap for named users. With neither set, a self service request may only ask for an empty permission list. `theauth.apiKeys.create()` and `trustedServerUse` callers are not capped. Malformed `permissions` values now answer 400.

  OIDC provider refresh token reuse now revokes the whole token family (RFC 9700 section 4.14.2). Migration `0012-oidc-refresh-family` adds a nullable `family_id` to `theauth_oidc_refresh_tokens` (OIDC provider enabled). Tokens issued before it fall back to revoking every refresh token of the same user and client on reuse. Run `theauth db up`.

  The admin API routes for audit events, delegations, user disable, sessions and revocations are now in the generated OpenAPI document, and the admin approval routes are documented as returning bare JSON, which is what they send. The drift test checks every admin route the plugin registers. The decision code lists in the Python and Go clients are generated from `DECISION_CODES` by `scripts/generate-openapi.ts`, with a drift test.

- 3e3855c: Added quorum (two person) approvals. `approval.request({ requiredApprovals: 2 })`, `approval.requiredApprovals` and `approval.quorum(request)` make a request need N distinct approvers (1 to 10, default 1). Approvers must differ from the requester and from each other, one denial ends the request, each approval writes its own audit row, and the argument bound hash, single spend and expiry apply to the whole quorum. `ApprovalQuorumError` carries the code `SELF_APPROVAL`, `DUPLICATE_APPROVER` or `APPROVER_REQUIRED`.

  The admin API `POST /approvals` takes `requiredApprovals`, and approve answers `status: "pending"` until the quorum is complete. The `approval.pending` webhook payload adds `requiredApprovals` and `approvalsReceived`, and a new `approval.vote` event reports progress. The dashboard inbox shows "1 of 2 approvals". Adds migration 0013 (`required_approvals` column and `theauth_approval_votes` table).

- a561306: Add a nullable `decision_code` column to `theauth_audit_logs` (not part of the audit hash, so existing chains stay valid). Every authorization row now records its decision code, `AuditEntry.code` exposes it, and `audit.query({ codes })` filters on it. A `beforeAuthorize` block, timeout or error now writes a chained audit row (code `hook_denied`, `hook_timeout`, `hook_error` or `approval_required`, with `theauthHook` details in `parameters`) and returns its id as `auditId`. `createTables()` migrates existing databases on startup; with `skipMigrations: true` apply `src/db/migrations/0002_add_audit_decision_code.sql` by hand before upgrading.
- 7adfac0: Audit input provenance and rotating pseudonyms.

  - `authorize`, `authorizeByToken` and `policy.evaluate` record where a call's inputs came from. Pass `context.inputs` with kinds `user_message`, `tool_output`, `retrieved_document` or `agent`, an optional id and the content (hashed and dropped) or a SHA-256. Only the hash is stored in `input_provenance`, merged with taint labels. `guardTool` takes the same list as an `inputs` option.
  - The argument name `inputProvenance` is now reserved in audit parameters, so tool arguments cannot plant a source.
  - `audit.query` takes `provenance: { kind?, hash? }`. `hashInputContent` computes the hash to look for.
  - New `audit.pseudonymRotation: { periodDays, retainPeriods? }` gives each subject a different pseudonym per period under a random per-period secret. Old period secrets are shredded, so a key holder cannot link a subject across periods. Chain verification and export keep working, and raw ids in a shredded period are no longer checked against their pseudonym.

- a561306: Audit receipts now have conformance coverage against the Go library, and the audit chain has published test vectors. The Go receipt fixture is vendored and verified in the normal test run, `packages/core/tests/fixtures/audit-chain-vectors.json` holds row hash vectors for hash versions 1 and 2 (generated by `scripts/gen-audit-chain-vectors.mjs`), and `docs/audit-receipts.mdx` specifies the leaf encoding and what does and does not interoperate with `theauth-go` (receipts do, the chains do not).

  Migrations and `skipMigrations` startup now throw `AUDIT_SECRETS_LAYOUT_MISMATCH` when `theauth_audit_secrets` already exists with a layout this library did not create, for example because `theauth-go` created it in the same database. The table is not touched. Databases that use only TheAuth are unaffected; if you hit the error, give each library its own database or schema.

  `chainPayload` is exported from the audit chain module so offline verifiers can build the exact hashed string.

- a561306: Audit rows now carry a millisecond write-order column, `recorded_at_ms` (migration `0003_add_audit_recorded_at_ms.sql`, applied by `createTables()`, existing rows backfilled), and `audit.query()` orders by it, so rows written in the same second come back in write order. The column is not part of the audit hash, so existing chains keep verifying. `delegation.revoke()` now writes a chained `delegation.revoke` audit row for each revoked link, cascaded links included. With `skipMigrations: true`, apply the 0003 file by hand. No documented read shape changes.
- a561306: Banning a user now revokes their MCP tokens. `admin.banUser` pushes a `sub` revocation for the user and an `agent` revocation for each agent they own through the shared revocation bus, so unbound access tokens, refresh tokens and agent bound tokens stop working on every instance. The same push now happens for `admin.deleteUser`, GDPR erasure (`gdpr.deleteUser`) and SCIM deactivation or deprovisioning. The `sub` row is a watermark: `admin.unbanUser` does not bring tokens issued before the ban back, and the owner's agents stay revoked. `createAdminModule`, `createGdprModule` and `createScimModule` take an optional revocation bus, and plugins receive it as `ctx.revocations`.
- a561306: `/mcp/revoke` answers 503 with `Retry-After` and `temporarily_unavailable` (RFC 7009) when the revocation store cannot record a revoke, instead of a 500; the freshness cache is still dropped and unknown tokens still get 200. `mcp.cimd.block` now writes a `client` revocation row, so the blocked client's tokens are refused at once in live mode. The optional `rememberMe` choice is plumbed through username sign in, magic link verify, passkey verify, the OAuth callback (via `?rememberMe` on authorize) and the sign in gate completions; absent means no change. `theauth doctor` gains `--fail-on info|warn|fail` and the `audit.secrets_table_collision` rule.
- 6fb281d: The dashboard gains an Explain page and a Revocations page, and the approvals inbox now says so when the approvals API is not mounted.

  Explain takes an agent id, action and resource and calls `POST /explain`, showing the decision code, the matched grant, constraint steps and the closest grants that nearly matched. Revocations shows the live `theauth_mcp_revocations` rows, the revocation bus counters, every live delegation link with the links and tokens a revoke would deny, and a revoke action for delegations, agents, users, clients and tokens. Every revoke is written to the audit log.

  Core `adminApi` adds `GET /revocations`, `GET /revocations/delegations` and `POST /revocations`. Security fix: `DELETE /delegations/:id` on the admin API now pushes the revoked links to the instance revocation bus. Before, only the chain rows changed, so MCP tokens tied to a revoked delegation stayed valid on other instances until they expired.

  Upgrade notes: mount the admin API at `/api` for the dashboard to reach the new routes. A core without them answers 404 and the page shows a short notice instead of failing.

- 3e3855c: Add `databaseHooks`: per-model `before` and `after` hooks for create and update on `user`, `session` and `account`. A `before` hook can return `false` to abort or `{ data }` to replace allowed fields, and it fails closed on a throw, a timeout or a malformed result (`DatabaseHookError`). `after` hooks run once the row is committed and never break the write. Hooks stay outside every single-use claim statement, so magic links, OTP codes, OAuth state and refresh rotation remain atomic. Exports `DatabaseHooks`, `DatabaseHookError` and `createDatabaseHookRunner`. See `docs/database-hooks.mdx`.
- 3e3855c: Add `database: { drizzle, dialect }` to pass an existing Drizzle instance (`"sqlite"`, `"postgres"` or `"mysql"`) instead of a URL. It goes through the same `DatabaseOpener` seam, migrations use the dialect, and `skipMigrations` works as before. See `docs/bring-your-own-drizzle.mdx`.

  Add `StoreConflictError`, exported from `@glinr/theauth`. The nine places that rely on a unique index (user create, audit chain append, quorum vote, ban insert, erasure tombstones, MCP client, revocation and block inserts) now read structured driver codes first and keep the text match as a fallback, so behavior on the current providers is unchanged.

  Fix SCIM group `PUT`: it deleted every member and re-inserted the list, so a member who stayed left the group for a moment, got a new row id, and lost any role other than `member`. It now removes only members missing from the list and adds only the new ones.

  `@glinr/theauth-test-utils` gains a `./store-contract` subpath with `runStoreContract`: claim races with 24 parallel callers, unique conflicts and audit chain order, for any backend. `vitest` is an optional peer dependency.

- d62a425: New subpath `@glinr/theauth/testing/devices`: a fleet simulator and conformance kit for devices. `createDeviceFleet({ size })` enrolls N simulated devices against a real in-memory theAuth through the real HTTP handler, with a virtual clock (`fleet.clock`) so runs are repeatable. `runDeviceConformance(fleet)` checks enrollment, assertions, bundle and revocation snapshot verification, offline and online use, clock skew, rollback and revocation in the middle of a session. Measured p50 and p99 at 1000 devices are in `docs/device-conformance-kit.mdx`.
- d62a425: SPIFFE bridge over HTTP, with audit rows. Set `devices.spiffe` (trust domains, audience, `agentMap` or `resolveAgent`, optional `clientCertificate` or `trustedProxyHeader`, `rateLimit`) and the handler serves `POST /device/spiffe/verify`, `POST /devices/spiffe/verify`, `POST /devices/spiffe/token` and `POST /devices/:id/spiffe`. They are in `sdks/openapi.json`.

  - Minting and linking are admin only. An X.509 chain is never read from the body of the device route, only from your `clientCertificate` callback or the one header you name in `trustedProxyHeader` (off by default, your proxy must overwrite it). Every route is rate limited per client and fails closed; the `rateLimit()` plugin has a new key `deviceSpiffe`.
  - Every verification outcome is reported to `onOutcome` and written to the audit log as `device.spiffe.authenticate` or `device.spiffe.verify` when it maps to a device or agent. Rows hold the SPIFFE ID, failure code and certificate thumbprint, never the certificate or token. `createSpiffeBridge` gained `onOutcome` and `verify()`.
  - Dashboard: the Devices page lists SPIFFE identities with their trust domain and can link an id.

- a561306: Add `theauth.explain(agentId, action, resource, options?)`. It mirrors `authorize()` and returns the decision code, the matched grant (own rule or the delegation link that carried it), the constraint checks, the delegation chain and the `beforeAuthorize` outcome, with no audit rows, no rate counter changes, no approval spend and no caching. `beforeAuthorize` only runs with `runHooks: true`, and receives `dryRun: true` and `source: "explain"`. Evaluation is shared with the simulator through `src/simulator/evaluate-set.ts`.
- a561306: `explain()` now returns `nearMisses`: when no grant matches, up to three own or delegated grants that failed on resource or action, each with a plain hint and a score (empty when `matchedGrant` is set). New `@glinr/theauth/testing` subpath with `createTestAuth`, `definePolicySuite`, `runPolicySuite`, `expectAllowed`, `expectDenied` and vitest matchers, and a new `theauth policy test <suite>` command (`--json`, `--config`, exit 1 on failure).

  Upgrade notes: `ExplainResult` gains a required `nearMisses` field. Code that builds an `ExplainResult` by hand needs `nearMisses: []`.

- a561306: Add `guardHook` and `composeBeforeAuthorize`, the external guard adapter contract. A guard such as HOL Guard implements `ExternalGuard.check(input, signal)`, receives the agent, request, full delegation chain, source, ip and `dryRun` (never the token), and returns a verdict. `guardHook` registers it through `beforeAuthorize` with the hook timeout and default deny; `composeBeforeAuthorize` combines several hooks with deny-overrides.
- a561306: `gdpr.deleteUser` now revokes every delegation link the user's agents give or receive (cascading to links further down, with `delegation.revoke` audit rows and revocation pushes) and keeps the revoked rows instead of deleting them, so downstream grants stop working. Delegation liveness also treats an agent whose inbound links are all revoked or expired as no longer self-standing: it lends only what its own permissions cover. Anonymized ids are now an HMAC-SHA256 (128 bits) under a per-instance secret (`hmacKey`, else the stored audit secret) instead of an unsalted SHA-256 prefix. Delete mode also clears `subjectId`, `actorId` and `approverId` on other users' audit rows that name the deleted user. `admin.deleteUser` no longer fails with a foreign key error when the user has agents: it goes through the same ordered erasure and keeps audit logs. User ids starting with `[deleted-` are reserved and rejected by `user.create`. Session creation refuses banned users (ban expiry honored) with a generic `UserBannedError` and a denied `sign_in` audit row, which covers password, username, magic link, passkey, OAuth, SAML and SSO sign-ins.
- a561306: Add `verifyGoAuditChain` to verify an audit chain exported by theauth-go from TypeScript. It rebuilds Go's hash input byte for byte (struct key order, HTML-escaped strings, microsecond timestamps, pseudonyms) and reports the first failure as `hash_mismatch`, `prev_hash_mismatch`, `seq_gap`, `seq_duplicate`, `unsupported_hash_version`, `pseudonym_mismatch` or `malformed_row`. It runs on Web Crypto only. The Go chain has no HMAC mode, so the verifier cannot detect a suffix rewritten by someone who can write the table, and it cannot detect truncation.

  The CLI gains `theauth audit verify-go <file.json|ndjson>`. Conformance vectors generated by the real Go code ship in the test fixtures.

- 2fab7c3: Add `verifyGoHeadCheckpoint` and `verifyGoHeadSignature` to verify the signed head checkpoint written by theauth-go (`checkpoint.CreateHeadCheckpoint`). Compared with rows exported from the Go log, it reports `chain_truncated` when a chain was cut off its tail (or is missing) and `head_mismatch` when the row at the signed position has another hash, after checking the Ed25519 signature, the domain separation and the sorted head list. Test vectors signed and judged by the real Go code ship in the test fixtures.

  `theauth audit verify-go` gains `--head <file> --head-key <file>` to run the head check next to the chain check.

- d6ce6fd: Faster hot paths, same answers. New migration `0014-hot-path-indexes` (run it with `theauth db up`, or let `createTheAuth` apply it) adds indexes for agent lookup by token hash, active agents per owner, permissions per agent, delegation links in both directions, the hourly rate limit read and the pending approval list. Without them these lookups scanned their table on SQLite and Postgres (MySQL already indexed the foreign key columns). On a SQLite file with 50,000 agents, 200,000 permissions and 50,000 delegation links, `authorize` through a three hop delegation chain went from about 10 ms to about 0.4 ms. Also: string HMAC secrets are imported once and reused (session cookies, MCP HS256 tokens), device bundle verification and signing reuse imported keys while the JWKS or JWK object is unchanged, the default resource matcher no longer splits strings, the approval hash canonicalizer skips work for plain strings, the delegation liveness walk reads each agent's inbound links once instead of twice, `agent.get` reads the agent and its permissions together, and the admin API pending approvals list reads quorum approvers in one query instead of one per request. Security checks are unchanged and each fast path is pinned to the code it replaced by tests. The measurements, method and noise are in `docs/performance.mdx`.
- a561306: Add the remote guard protocol. `httpGuard({ name, url, secret })` turns an HTTPS endpoint run by a guard vendor (for example HOL Guard) into a `beforeAuthorize` hook. Requests are signed with HMAC-SHA256 over `<timestamp>.<body>` (`x-theauth-timestamp`, `x-theauth-signature: v1=<hex>`), responses must be signed too (`x-theauth-response-timestamp`, `x-theauth-response-signature: v1=<hex HMAC-SHA256 of "<requestId>.<responseTimestamp>.<body>">`, bound to the request id, same replay window, required by default, `requireSignedResponse: false` opts out for local development only, optional `responseSecret`), responses are validated with a strict schema, redirects are never followed, plain http is refused outside localhost, and every failure denies through the existing hook runner. `verifyGuardRequest(secret, headers, body)` and `signGuardResponse(secret, { requestId, body })` are exported for vendors.

  `@glinr/theauth-conformance` gains guard mode: `npx @glinr/theauth-conformance guard <url> --secret <s>` runs 12 checks (unsigned, wrong signature and stale requests refused, unsigned, wrongly signed, wrong request id and stale responses failed, canary allow and deny verdicts, malformed input never allowed, dryRun, no redirect, latency budget), plus a reference guard server, `startGuardReference`.

  Upgrade notes: additive, nothing changes unless you call `httpGuard`. Vendors must sign their responses. The request body carries the agent, action, resource, arguments and delegation chain, so use the `redact` option to drop user data before it leaves the process. See docs/guards.mdx.

- fe7e6c6: Input provenance end to end.

  - Content hashes in `input_provenance` are now HMAC-SHA-256 under an HKDF subkey of the audit key (version tag `hv: 2`). Old plain hashes still match. `hashInputContent(content, auditKey)` takes the key now, `hashInputContentPlain` is the old function (breaking for callers that hashed themselves, see `docs/upgrading-to-2.mdx`).
  - `audit.query({ provenance: { content } })` hashes on the server and matches keyed and plain rows. `AuditEntry.inputs` exposes the recorded sources.
  - `POST /authorize` and `POST /authorize/token` accept `inputs` or a `TheAuth-Inputs` header. `GET /audit` takes `provenanceKind`, `provenanceHash` and `provenanceContent`. `sdks/openapi.json` is regenerated.
  - Gateway reads `TheAuth-Inputs`, records it on permission checks and audit entries, and strips it before the upstream. The admin MCP server reads `_meta["io.theauth/inputs"]` and `query_audit` takes provenance filters.
  - `theauth audit query` with `--provenance <kind>[:<hash>]` and `--input-content`, and an Inputs column with chips on the dashboard audit page.
  - `policy.taint.inputLabels` (off by default) turns the kinds of `context.inputs` into `input:<kind>` call labels, so a taint rule can hold a tool such as `tool:exec` for approval after a retrieved document was in context.

- fe7e6c6: IoT devices as principals (`theauth.device`, opt in with `devices` in the config). A device is backed by an agent row of type `device`, so permissions, constraints, delegation, the revocation bus and the audit chain apply unchanged.

  - Credentials: pre shared keys (`tdk_`, stored as SHA-256), public keys that sign `device-assertion+jwt` assertions (RFC 7523 layout, DPoP style `jti` replay cache), and TLS client certificate thumbprints (`x5t#S256`, RFC 8705) supplied by the host.
  - Enrollment with single use claim codes or bulk tokens with a use limit, claimed atomically, plus an attestation hook with single use nonces (RFC 9334 freshness).
  - `device.authorize` with device states (`device_suspended`, `device_revoked`, `device_expired`, `device_not_found`) and `theauthPrincipal` on every audit row.
  - Signed offline policy bundles (`device-policy+jwt`, ES256 or EdDSA, one hour default, 24 hour cap, rollback protected), with `verifyDeviceBundle` and `evaluateDeviceBundle` for the device side.
  - HTTP routes under `/devices` (owner scoped) and `/device` (device facing), OpenAPI metadata, migration `0010-devices`, and `theauth device` in the CLI.

  Also fixed: agent registration tokens stored any `agent_type` string the caller sent; only `autonomous`, `delegated` and `service` are accepted now. The OpenAPI generator supports discriminated unions.

- 3e3855c: Add `supabase` and `workos` sources to the user importer and `theauth migrate`. Supabase reads `auth.users` rows (JSON or CSV, with optional `auth.identities`) and keeps bcrypt `encrypted_password` hashes for lazy migration. WorkOS reads List users API output and accepts an optional support-provided hash file, because the API returns no hashes. New guides: `migrate/from-supabase` and `migrate/from-workos`.
- dd6b30e: MySQL dialect fixes. The MySQL DDL is now generated from the portable baseline: key, unique, defaulted and referenced `TEXT` columns become `VARCHAR(191)`, inline `REFERENCES` become table level `FOREIGN KEY` clauses (MySQL ignored the inline form), `CREATE INDEX IF NOT EXISTS` loses the unsupported clause, and every table uses InnoDB, utf8mb4 and a binary collation so tokens and ids match exactly. The migration ledger stores `UTC_TIMESTAMP(3)` and the MySQL pool connects with `timezone: "Z"`.

  Single use claims (magic link, OTP, one time token, OAuth state, refresh token, session refresh, approvals) no longer call `RETURNING`, which the MySQL query builder lacks. They go through the new `claimCount` helper in `src/db/claim.ts`, which uses `RETURNING` where it exists and the affected row count otherwise. SQLite and Postgres behavior is unchanged.

  `provider: "mysql"` still requires `experimental: true`: the gate stays until the contract suite (`THEAUTH_TEST_MYSQL_URL`) has passed against a real MySQL 8.4 server. The suite has not been run against one yet. MySQL migration checksums changed, which affects nobody because no MySQL database could be created before.

- a561306: Add observability. `observability.onDecision(event)` receives one typed event per `authorize`, `authorizeByToken` and `policy.evaluate` decision (agent, owner, action, resource, decision, code, duration, cache hit, delegation depth, hook outcome, guard). It runs in a queued microtask, so it never delays or changes a decision, and a throwing listener is swallowed and counted (`theauth.observability.stats()`). Events carry no tokens and no raw arguments, and `observability.redactResource` rewrites the resource string. A new `logger` option (`debug`, `info`, `warn`, `error`, no-op by default) receives hook timeout and listener failure warnings.

  `@glinr/theauth-plugin-telemetry` adds `theauthOtel({ tracer, meter })`: the `theauth.decisions` counter, the `theauth.decision.duration` histogram, one span per decision, and span events for hook timeouts. No new dependency.

  The dashboard audit page gains a Code column, a code filter, and a Why drawer that calls `POST /explain`.

  Upgrade notes: additive, nothing changes unless you set `observability` or `logger`. The dashboard sends `codes` to your audit endpoint and calls `/api/explain`, so mount the HTTP handler at `/api`. See docs/observability.mdx.

- 3953479: Opt in path aware resource matching: `resourceMatching: "path"` on `createTheAuth` (and `policy.resourceMatching` for the policy engine). Inside a colon segment `/` separates path segments, `*` matches one, `**` matches one or more, never an empty, `.` or `..` segment. The default is unchanged. Device bundles carry the mode (`rm` claim), `theauth ros2 export` takes `--resource-matching path` and `--single-level skip|widen`, `--robot` includes delegated permissions, and `--enclave-cert` sets the grant window from the certificate.

  Security fix: the delegation subset check accepted a child resource longer than an exact parent resource (parent `tool:db`, child `tool:db:secrets`), which gave the child access the parent did not have. It now uses the runtime matcher. Also, with the default matching, `devices.register` and `devices.update` refuse a `*` that is not the last segment of a device resource.

- a561306: Postgres now works across the whole instance. Before this release the core modules sent SQLite-shaped values to Postgres, so the first write (for example `user.create`) and every JSON read failed.

  Timestamps on Postgres are now `BIGINT` epoch seconds, the same as SQLite. JSON stays `JSONB` and flags stay `BOOLEAN`. Migration `0003-epoch-timestamps` converts existing `TIMESTAMPTZ` columns in place. Run `theauth db up` (or let the instance migrate on start) after upgrading. If you query the tables yourself, wrap timestamp columns in `to_timestamp(...)`.

  MySQL is marked unsupported until it passes the test suite on a real server. `provider: "mysql"` now throws `THEAUTH_MYSQL_UNSUPPORTED` unless you pass `experimental: true`.

  Audit hashes are unchanged, so existing chains keep verifying.

  Fix: the refresh token `used` column (`theauth_refresh_tokens`) holds the consume time in epoch seconds, which the reuse grace window reads. It was typed as a 0/1 flag (`BOOLEAN` on Postgres), so the grace window never matched and every replay was treated as theft. It is now `BIGINT` on Postgres and MySQL (SQLite storage is unchanged).

- f5616dc: Add ROS 2 and robotics authorization.

  `@glinr/theauth/robotics` is a new subpath. It maps theAuth permissions on `ros2:/topic`, `ros2:srv:/service` and `ros2:action:/action` resources (actions publish, subscribe, call, reply, execute) to the SROS2 policy format and to DDS Security 1.1 permissions and governance XML, the way SROS2's own `permissions.xsl` does. `exportRos2`, `buildRosPolicy`, `diffRosPolicies` and the XML writers are pure functions. Permissions that carry constraints DDS cannot enforce (approval, step up, rate, time window, IP, argument patterns) are left out of the static grant by default and reported as gated.

  `guardRobotCommand` checks a command against `POST /authorize/token` and runs it only on an explicit allow. It fails closed on every error and lets an explicit, exact match list of safety stop resources through without a network call.

  The CLI gains `theauth ros2 export` and `theauth ros2 diff`. Exported XML is unsigned. The docs page `robotics-ros2` has the signing commands, an rclpy gate node and an rclcpp sketch.

- 701a372: `theauth ros2 export` now adds the endpoints every ROS 2 node opens at start (`/rosout`, `/parameter_events` and the node's six parameter services). Without them a node under `ROS_SECURITY_STRATEGY=Enforce` fails at creation, which was observed on ros:humble with Fast DDS. Use `--node` and `--namespace` to name the node, or `--no-node-baseline` to leave them out. In the library, pass `nodeBaseline` to `exportRos2` (off by default there).
- 3e3855c: Add three secondary storage backends: `mongoStorage(collection)` for MongoDB 4.4+, `sqlStorage({ dialect, run })` for any SQL database including Microsoft SQL Server, and `kyselyStorage(db, { dialect, CompiledQuery })` for any Kysely dialect. None adds a dependency; you pass your own client. All keep exact per key counters and follow the same `SecondaryStorage` contract as the memory, database and Redis backends.

  Fix: `redisStorage().incr()` threw `value is not an integer` when the key held plain text written by `set()`. It now restarts the window like the other backends.

- a561306: Secret rotation for webhook signing, the session cookie cache and stateless session cookies. New `SecretRing` (and `createSecretRing`) in the crypto module: `secret` can now be a string or `[current, ...previous]`, entries may be `{ id, secret }`. The first secret signs and encrypts, every secret verifies and decrypts, so changing a secret no longer invalidates everything already issued.

  - Webhooks: endpoint `secret` accepts the list form, deliveries add an optional `X-TheAuth-Key-Id` header when the current key has an id, and `verify` accepts a list plus an optional `keyId`. Plain string secrets behave as before.
  - `createSessionCookieCache` and `createStatelessSessions`: `secret: string | string[]`. The key id, when set, is appended to the cookie value. The string form is unchanged.
  - Construction rejects empty and duplicate secrets and secrets under 32 bytes (a plain webhook string keeps its old no minimum rule). Secrets are never logged or included in error messages.

- a8284dc: API keys: when `apiKeys` has no `grantablePermissions` and the `org` module is on, a self service key is now capped by the creator's org roles through `org.hasPermission`. Before, every non-empty permission list was refused. Still fails closed with no org membership, no org module or a failing lookup.

  `theauth doctor --security` adds seven findings: `sec.api_keys.no_scope_resolver`, `sec.device.path_matching_off`, `sec.device.mid_wildcard`, `sec.device.bundle_ttl_long`, `sec.device.no_attestation`, `sec.approval.no_step_up` and `sec.agent.dpop_not_required`.

- a561306: Add an opt-in session idle timeout and remember me. `idleTimeoutMs` (env `THEAUTH_SESSION_IDLE_TIMEOUT_MS`, off by default) denies a session with no recent activity; `lastActiveAt` is rewritten at most once per `activityGranularityMs`. `session.validateDetailed(token)` and the cookie manager's `validateSession` report a `reason` (`idle_timeout`, `expired`, `not_found`, `invalid_token`). `create(userId, metadata, { rememberMe })` gives a longer capped lifetime (`rememberMeMaxAge`, `rememberMeMaxAgeCap`), and `buildSessionCookie` writes a persistent or browser session cookie to match. No schema change: the stamp lives in session metadata. The signed session cookie cache stays opt-in on `createCookieSessionManager` and is now documented as experimental and not revocation safe.
- 3e3855c: Add `vonageOtpSender` and `plivoOtpSender` next to `twilioOtpSender`. All SMS senders now time out after 10 seconds (`timeoutMs`) and their errors carry only the HTTP status and the vendor error code, no response body, so phone numbers and codes cannot reach logs.
- 372a4ec: SPIFFE workload identity bridge. `createSpiffeBridge` verifies an X.509-SVID (one `spiffe://` URI SAN, leaf rules of the X509-SVID spec, path validation against a configured trust bundle) or a JWT-SVID (audience checked, short expiry) and maps the SPIFFE ID to an existing device or agent. An X.509-SVID also yields the RFC 8705 `x5t#S256` confirmation, and an agent can get a token bound to the certificate with `bridge.issueAgentToken`. Trust bundles can come from static roots, a bundle document, or a SPIFFE bundle endpoint refreshed on demand (https only, size and time limits, rollback guard on `spiffe_sequence`, fail closed when stale).

  Devices get a new credential kind `spiffe` (`device.addCredential(id, { kind: "spiffe", spiffeId })`, owner side only, enrollment refuses it) and `device.findBySpiffeId`. The CLI gains `theauth device spiffe verify-x509`, `verify-jwt` and `link`. The dashboard credential type lists the new kind.

- 3953479: Step-up follow-ups. `POST /auth/passkey/step-up/options` and `/auth/passkey/step-up/verify` re-authenticate the current session with a passkey, with no second session, and refuse a credential that belongs to another user. Social sign-in now records a `federated` method (`amr` `fed`, single factor) and adds the provider's registered RFC 8176 `amr` hints from its ID token without ever raising `acr`. The headless `totp.handleRequest` and `passkey.handleRequest` handlers now record a step up on the caller's own session. `AuthMethod` gains `"federated"`, `AuthEvent` gains optional `idpAmr`, and `CreateSessionOptions` gains `idpAmr`. `mcp/types.ts` and `theauth-core.ts` are split under 500 lines with the same exports. See `docs/step-up-auth.mdx`.
- a561306: Add opt-in typed permissions. `definePermissions({ "mcp:github:*": ["read", "write"] })` declares a catalog, and passing it as `createTheAuth({ permissions })` returns a `TypedTheAuth<C>` where `authorize`, `authorizeByToken`, `agent.create`, `agent.update` and `delegate` only accept declared resources and actions, so typos are compile errors. Instances created without `permissions` are unchanged. The catalog is not enforced at runtime. Also adds `TheAuthConfig.permissions`.
- a561306: Add `theauth.user.create({ email, name?, id?, metadata? })` and `theauth.user.get(idOrEmail)`. `create` validates the email with zod, lowercases it, and generates an id when none is given. For the same email it returns the existing row unchanged. It throws `UserError` with code `USER_EMAIL_CONFLICT` when the requested id differs from that row's id, and `USER_ID_CONFLICT` when the requested id belongs to another email. Invalid input throws `USER_INVALID_INPUT`. The quickstart no longer needs a hand-written insert into `theauth_users`.
- a8284dc: Added `GET /devices/enrollment-tokens` and `devices.listEnrollmentTokens()`, which list tokens with usage and state and never the plaintext. The dashboard Devices page now lists enrollment tokens with a revoke button, and a device can have its groups edited, a credential added or revoked, and a policy bundle issued. The dashboard client no longer reports a network error for a 204 response.

  `DELETE /delegations/:id` now answers 204 on the admin API plugin too (it used to answer 200 with `{ revoked }`), sharing one handler with the core route. See the upgrade guide.

- 84ebfb8: `verifyGoAuditChain` now understands the rotating pseudonyms of theauth-go (`r1:<period>:<hex>`). Before, a row written with rotation on reported `pseudonym_mismatch` whenever `pseudonymSecret` was given. A new `periodSecrets` option (object or `Map` keyed by period) checks them, a period without a secret is trusted as stored and counted in `pseudonymsUnchecked`, and `theauth audit verify-go` gains `--period-secrets <file>`.

  The approval hash is now byte for byte the one theauth-go computes for JSON shaped arguments: keys sorted by UTF-8 bytes, Go's string escaping, `-0` kept, a bigint written as digits. `NaN`, `Infinity` and other unhashable values now throw, so the call is denied instead of hashing like `null`. Shared vectors written by the real Go code, plus an end to end vector (real Go chain, rotating pseudonyms, signed head, truncation cuts) ship in the test fixtures.

- 2d1bd9a: Built in attestation verifiers for the device enrollment hook. `createAppleAppAttestVerifier` follows Apple's attestation object validation guide (CBOR object, certificate chain to the Apple App Attestation Root CA, nonce over authData and the client data hash, key id, App ID hash, counter, AAGUID) and binds the enrolled key through the client data. `createTpm2QuoteVerifier` checks a TPM 2.0 quote (restricted resident signing key, qualifying data equal to the nonce, RSASSA or ECDSA signature, PCR digest, optional certificate chain). Both use Web Crypto only and refuse on any doubt. The CLI gains `theauth device attest apple` and `theauth device attest tpm`. Tested against real fixtures: Apple's own sample plus two device recordings for App Attest, and real Google Compute Engine vTPM quotes for TPM. The IoT docs say what that does and does not cover.
- 8a0aade: `databaseHooks.user.update` now fires for admin ban, unban and forced password reset, additional fields, email verification, anonymous upgrade, SCIM replace, patch and deactivate, and Stripe and Polar billing writes. `databaseHooks.user.create` now fires for anonymous, username, Google One Tap and SCIM sign-ups. Semantics are the same as before: `before` fails closed, only `email`, `name` and `metadata` can be replaced, `after` errors are swallowed, and no hook runs inside a single-use claim statement. A SCIM write stopped by a hook answers 403, a billing webhook stopped by a hook answers 500 so the provider retries. Also fixes magic link and email OTP sign-ups ignoring a `name` or `metadata` replacement from a `before` hook. GDPR erasure, `deleteUser` and the importers deliberately bypass hooks.
- 6bdec47: Device attestation goes further. A permission can now demand a hardware attested device: `constraints.attestation` takes `minSecurityLevel` (`hardware` or `strongbox`), `bootState` and `appIds`, and is decided against facts the server derives from the verified claims stored at enrollment (`attestationFacts`). It applies in `device.authorize`, in signed offline bundles (the new `att` claim) and in delegation (a child can only narrow it), fails closed for agents, users and devices without evidence, and denies with the new code `attestation_required`. The HTTP permission schemas accept it and reject unknown fields.

  Apple App Attest: `verifyAppleAssertion` checks an assertion (signature over `authenticatorData` and the client data hash, `rpIdHash`, counter), `device.verifyAppAssertion` runs it for an enrolled device and advances `theauth_devices.app_attest_counter` with one conditional update (migration 0015), so the same assertion works once. `verifyAppleReceipt` checks Apple's fraud receipt (CMS signature, chain to Apple Root CA G3, app, key, expiry) and returns the risk metric. The verifier now returns the `attestedPublicKey` claim. Tested on real recordings from veehaitch/devicecheck-appattest and block/buzz.

  TPM 2.0: `tpm2MakeCredential` and `device.tpmActivationChallenge` (route `POST /device/tpm-activation`) run the credential activation handshake, and `createTpm2CertifyVerifier` checks TPM2_Certify of the enrolled key plus the activation. Credential blobs were accepted by TPM2_ActivateCredential on a software TPM (swtpm) for RSA and ECC endorsement keys.

  The dashboard shows verified attestation claims in the device detail panel. `theauth device attest` gains `apple-assertion` and `apple-receipt` and prints the policy facts of accepted evidence.

- 7a9dfac: Signed revocation snapshots for offline devices. With `devices.revocations` set, `issueBundle` (and `GET /device/bundle`) returns a signed list of the owner's revoked and suspended device ids next to the policy bundle. `verifyDeviceBundle({ revocations })` refuses a bundle with `revoked` when the device is listed and with `stale_revocations` when the snapshot is missing, expired or older than `maxAgeSeconds`. `verifyRevocationSnapshot` answers membership for peers. The Go package `iot/device` verifies the same format against shared vectors.

  Built in Android Key Attestation verifier for the enrollment hook: `createAndroidKeyAttestationVerifier` and `googleRevocationList`, plus `theauth device attest android` in the CLI. Tested against the real chains in google/android-key-attestation, see the IoT docs for what that does and does not cover.

  Behavior change: attestation evidence without a nonce is now refused unless `attestation.requireNonce` is false, and the hook input carries `credentialKind` and `credentialKeyThumbprint`. See the upgrade guide.

- 6bdec47: Email and password in core. A new top-level `emailPassword` config key stores a real email in `users.email` and serves `POST /auth/email/sign-up`, `/sign-in`, `/verify`, `/resend-verification`, `/forgot-password`, `/reset-password` and `/change-password` from `createTheAuthHandler`. It reuses the username credential table, hashing, lockout and sign-in gate, and issues ordinary core sessions with the session cookie. Verification is on by default (it needs `emailVerification`): sign-up creates no session, sign-in answers `EMAIL_NOT_VERIFIED` only after the password checks out, and a sign-up for a taken address answers like a new one and never attaches a password to the existing user. A completed password reset marks the address verified.

  Client bindings: `emailPassword: true` on the session store, React `managed`, the Vue plugin, the Svelte client, the Expo provider config and the Electron provider points them at the new routes. Sign-up now reports `verificationRequired`, failed results carry the server `code`, and the store, React (`useEmailPassword`), Vue and Svelte expose `verifyEmail`, `resendVerification`, `requestPasswordReset` and `resetPassword`. React `signUp` resolves to `data: { verificationRequired }` instead of `data: undefined`. `@glinr/theauth-react` also splits `context.tsx` into smaller files with no behavior change.

  Fixes: `emailVerification` alone no longer fails with "no such table" (the one-time token table is now created for it). `@glinr/theauth-email` is deprecated: its sign-in token is not a core session (`GET /auth/session` answers 401, no cookie is set) and its sign-up returned a session token before verification. Use `emailPassword`.

- d62a425: Add `advanced.database.generateId` to choose how user, session and OAuth account ids are made: `"uuid"` (default), `"uuidv7"` (time ordered, RFC 9562, monotonic within a millisecond) or `({ model }) => string`. Results are validated (1 to 191 characters, `A-Z a-z 0-9 _ - .`). Database generated ids (`false`, `"serial"`) throw `THEAUTH_ID_UNSUPPORTED` because every table stores and references ids as text. Exports `generateUuidV7` and `IdGenerationError`.

  Also: the Google One Tap plugin now builds its session manager with the configured `databaseHooks`, so session hooks run for One Tap sign in.

- d62a425: Add `database: { provider: "libsql", url, authToken? }` for Turso and other libSQL servers (or a `file:` URL), backed by the optional `@libsql/client` peer. It migrates with the SQLite schema. The store contract suite passes on a real libSQL file through the provider and through a bring your own `drizzle-orm/libsql` handle. Docs: a new Turso, Neon and Supabase page with a Neon recipe over the WebSocket `Pool`, Supabase connection modes and SSL spelling with `pg` 8.20, and what was run. Adds an opt in contract test for Postgres behind a transaction mode pooler (`THEAUTH_TEST_PG_POOLER_URL`).
- d62a425: Add `createCloudflareProvider` (Sign in with Cloudflare, profile from the Cloudflare API `/user`, basic or post client auth) and `createPaybinProvider` (Paybin OpenID Connect with PKCE) to `@glinr/theauth/auth`. Docs: provider pages for both, and Nitro and Waku integration recipes that run against the real frameworks with no new package.

### Patch Changes

- 8bff5af: Fix the hourly call budget (`maxCallsPerHour`, table `theauth_rate_limits`). It read the counters and then wrote one back, so parallel calls could all see room and pass the limit (24 parallel calls against a limit of 10 all got through). The count is now reserved first with one guarded increment (or an insert on a deterministic bucket id), then summed, and a call over the limit hands its slot back. It uses the store kernel on SQLite, Postgres and MySQL. A call may be refused when it would have just fit, but the budget is never exceeded. The store contract suite gains a 24 way race for it.

  Also declares the migration 0014 hot path indexes in the Drizzle schema objects.

- 746da30: Quorum approvals follow-ups. The Prisma adapter gains `requiredApprovals` on `TheAuthApprovalRequest`, a `TheAuthApprovalVote` model and `castApprovalVote` / `listApprovalVotes`, with the same single vote guarantee as core (composite primary key plus one conditional `updateMany`). A new `theauth approvals` command (list, show, approve, deny, request with `--required-approvals`) drives the admin API. The Python and Go clients send `requiredApprovals` and read `requiredApprovals`, `approvalsReceived` and `approvers`. Fixed: when concurrent votes pushed the count past the quorum, the completing call reported every counted approver and recorded itself as the responder. It now reports the first `requiredApprovals` approvers.
- a561306: Audit chain verification no longer trusts records anyone with database write access could write.

  - `audit.erasure` records are now appended to the agent's hash chain, and every entry carries an HMAC (audit key) over the erased row's id, seq, hash, previous hash, hash version and erasure reason. For an anonymized version 1 row the entry also pins the hash of the row as erasure left it, so editing it later is still tamper. `verifyAuditChain` recomputes the MACs and reports `erasure_unchained` or `erasure_forged` instead of excusing the gap or edit. Unsigned erasure records from earlier unreleased 2.0 builds are not accepted and there is no compatibility path for them.
  - A chained row whose `hash_version` was rewritten to NULL or 1 is reported as `version_downgrade`.
  - Deleting the oldest rows of a chain is reported as `truncated_prefix`. A chain may start at seq 1, after a retention checkpoint (now HMAC signed), or at an anchor written by the new `theauth.audit.checkpoint()`, which also returns anchors and heads to pin outside the database. `verifyAuditChain` accepts them as `anchors` (`anchor_mismatch` when a pinned row changed) next to `expectedHeads`. `allowUnanchoredPrefix: true` restores the old lenient start check.
  - `theauth.audit.verifyAuditChain` is now on the public `audit` facade, as the docs already showed.
  - Tool arguments can no longer plant system fields in audit `parameters`: `approvalId` and every key starting with `theauth` are stripped from caller arguments before they are written.

- a561306: Close the DNS rebinding race in the client metadata document fetcher on Node and Bun. `safeFetchJson` now connects through `node:https` (loaded by a guarded dynamic import) pinned to the addresses it already vetted, so the name is never resolved a second time. Each address is vetted again at connect, one non-public address in a multi-address answer refuses the whole answer, TLS still validates the original hostname, keep-alive is off, and `HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY` are not used on that path. Workers, Deno, a custom `fetchImpl` and `pinnedConnect: "off"` keep the `fetch` path and the documented residual risk. New options: `pinnedConnect` and the test-only `caForTests`.
- a561306: Security hardening found in review. These fix issues in the unreleased 2.0 work, not in a published release.

  - Approvals are bound to the action, resource and arguments the human approved. Spending one with different arguments is denied with `APPROVAL_ARGUMENTS_MISMATCH`. An approval created without arguments covers only an argument-less call.
  - A delegation covering several actions no longer drops the parent's `requireApproval` for any covered action. Constraints are now inherited per action, and a grant is split when actions carry different constraints.
  - An in-process guard that returns `undefined`, `null` or any non-verdict value now fails closed as a deny instead of an allow.
  - An invalid `expiresAt` (Invalid Date, NaN, non-finite, wrong type) now throws a `ValidationError` at agent create, agent update and delegation grant, instead of being stored as NULL (never expires).
  - `toleranceSec` must be a finite number between 0 and 3600. `httpGuard` rejects anything else at config time and the verify helpers fail closed.
  - The guard HTTP client now enforces the 64 KiB response cap while streaming and aborts once exceeded.

- a561306: `theauth.delegation.revoke(chainId, opts?)` now accepts `{ revokedBy }` and forwards it, so the `delegation.revoke` audit rows record who revoked the chain instead of null.
- 8bff5af: The Android Key Attestation, Apple App Attest and TPM 2.0 quote verifiers now refuse an empty string nonce, like the Go port does. An empty nonce used to pass the "nonce is missing" check, and a TPM quote with empty qualifying data would then match it.
- 6bdec47: Close account pre-hijacking through email matching (GHSA draft pending).

  - Google One Tap linked a sign-in to any existing account with the same email, ignoring `email_verified` and the local verification state. It now needs both sides verified, matches the address case-insensitively and stores new users as verified only when Google says so. Otherwise it answers 409 `ACCOUNT_EXISTS`.
  - Magic link and email OTP now mark the address verified on redemption. On an account that was still unverified they delete the password, linked providers, passkeys and sessions created before the mailbox was proven, so an earlier sign-up with the victim's address no longer survives the victim's first sign-in.
  - New options: `unsafeAllowUnverifiedEmailLinking` on `oneTap()` and `oauth()`, `keepUnverifiedCredentials` on `magicLink` and `emailOtp`. All default to the safe behavior.
  - Fixed the OAuth docs, which still said new users are always stored as verified.

- 746da30: `gdpr.deleteUser` is now resumable and idempotent. It runs as ordered steps with a progress marker, so a crash or database error halfway is finished by calling it again, and two concurrent calls leave one clean result. Audit erasure writes each `audit.erasure` record once (deterministic id) and rewrites rows per agent in a rerun-safe order. `gdpr.anonymizeUser` applies its credential deletes and user update as one atomic batch. `organization.remove` is one atomic batch. Fixes along the way: revoking a delegation link writes its audit row before flipping the status and `revokeAllForAgent` resumes cascades through already revoked links, and `exportUserData` no longer drops audit rows for users who own no agents.
- a561306: Fix a privilege escalation in the unreleased MCP token exchange binding (2.0 work). No published release is affected: the exchange binding was never released.

  - Token exchange now checks that the subject token's user owns, or reaches over live delegation links from an agent they own, every agent the child token names (the presenting client's agent, the actor token's agent and every hop). Otherwise it returns `invalid_grant` and writes a `mcp.token_exchange` denied audit row under the refused agent.
  - An exchanged token's `agent_id` and `principal.agent` are now the acting agent, the last entry of `theauth_dlg.agt`, never the presenting client's agent outside the binding. Validation refuses a bound token whose `agent_id` is not in `agt`.
  - Ordinary tokens of a client bound to a delegated agent now name the agent's live inbound path in `theauth_dlg` (`agt: [root, ..., agent]`, one `lnk` per hop), so revoking a parent delegation is seen in cached mode and on `revalidate()` in offline mode, not only in live mode.
  - Exchanged tokens carry `theauth_pjti`, the jtis of their subject token lineage. Revoking a parent token (RFC 7009, or its refresh family) now revokes every token exchanged from it. The `theauth_dlg` version stays `1`; validators that predate the new claim ignore it.

- 31e5ae6: A request that arrives while the MCP module is still writing its `preRegisteredClients` now waits for them instead of answering `invalid_client` for a client that is configured. A failed pre-registration write is thrown to the first client lookup, not lost.
- a561306: Fix a revocation bypass in the unreleased 2.0 MCP revocation work. No public release is affected, because the revocation binding was never released.

  The token endpoint now checks the revocation store, live, before minting from a refresh token or an authorization code: the token's `jti`, the subject (sign out everywhere, ban, delete), the client (CIMD block) and the bound agent. A hit is refused with `invalid_grant` (and kills the refresh family); a store error fails closed with `server_error`. When refresh token reuse is detected, or a refresh token is revoked through `/mcp/revoke`, the access tokens already minted from that family are now denylisted by `jti` (with their own expiry so the rows can be pruned), so a thief's access token stops working at once. `revokeTokenFamily` store functions may return the family's `{ jti, expiresAt }` list; the database store does.

- a561306: MCP revocation reliability. The revocation bus no longer reads a bare `process.env`, which threw on Cloudflare Workers and Deno and silently dropped every `sub` and no-expiry `agent` push (new `getEnv` helper). A push now clears the local freshness cache before it writes (and again after), a retried push logs a warning, and `auth.revocations.stats()` gains `attemptFailures` and `pruned`. The denylist is pruned opportunistically after writes (at most once per `revocation.pruneIntervalMs`, default 60 s, in LIMITed batches) and by `auth.revocations.prune()` for cron. The cached mode poll no longer runs `COUNT(*)` over the table. A cached read that was in flight when a revoke landed, including callers that joined it, now recomputes instead of returning the stale "live". New `revocation.clockSkewMs` (default 0) widens the `sub` and `client` watermark so a revoker with a lagging clock still kills tokens minted just before it. Access tokens already expired by more than a minute no longer get a denylist row.
- 2d27ad0: The cookie session manager now checks the session expiry during refresh against the clock you pass in `now`, not the real clock. Production behavior is unchanged when `now` is not set.
- a561306: Fix the permission simulator dropping `constraints` on delegated permissions. A delegated rate limit, IP allowlist, time window or approval rule could show `allow` in `simulate()`, `simulateMany()` and `effectivePermissions()` while `authorize()` denied. The simulator now keeps delegated constraints and agrees with `authorize()`.
- bd34fa9: SPIFFE admin routes no longer reveal another owner's inactive agent. `POST /devices/spiffe/verify` now answers `unknown_workload` with the same text as an unmapped id, and `POST /devices/spiffe/token` checks ownership before it says a device is the wrong kind of workload or an agent is inactive. A failed bridge result for an inactive agent carries the `agentId` so routes can check the owner.
- 6bdec47: Docs: Effect (3 and 4), Encore.ts and Convex integration recipes, each run against the real framework. They use the core HTTP handler, so there is no new package. Convex verifies theAuth tokens through a custom JWT provider, because theAuth needs a SQL database that Convex does not offer.
- 6bdec47: Opt-in real-endpoint tests for Turso, Neon and Supabase (`packages/core/tests/store-contract/hosted.test.ts`). Each suite is skipped unless its variable is set (`THEAUTH_TEST_TURSO_URL` and `THEAUTH_TEST_TURSO_AUTH_TOKEN`, `THEAUTH_TEST_NEON_URL`, `THEAUTH_TEST_SUPABASE_URL`), and `THEAUTH_TEST_HOSTED_RESET=1` drops the `theauth_*` tables around a run. Documented on the hosted databases page.
- 6bdec47: Audit writes now go through a repository (`readHead`, `appendAt`, `insertUnchained`) on the store layer, and the per agent write queue lives on the stores object instead of a map keyed by the Drizzle handle. Behavior is unchanged on the Drizzle path. A Kysely kernel (Postgres, MySQL, SQLite, SQL Server) and generated SQL Server DDL for the core tables exist as internal code, tested against the store contract on all four engines. They are not exposed as a `database` option yet, because most of core still queries through Drizzle (see Choose a storage backend). `kysely` is an optional peer dependency for that code.

  Fixes:

  - MySQL: `deviceEnrollments.spendUse` read the row back with its own filters after incrementing, so the last allowed use of an enrollment (and any use that made `uses` reach `maxUses`) read as refused while the use was still consumed. A one use enrollment could not be redeemed. The increment now reads its own value through `LAST_INSERT_ID(expr)` on one connection, which also stops a concurrent caller's value leaking into the result.
  - Audit rows: a NUL character (U+0000) in a text or JSON field made Postgres refuse the insert, and made sql.js cut the string so the stored row no longer matched its hash and the chain failed verification for good. NUL is now replaced with U+FFFD before the row is hashed, on every backend.

- fe7e6c6: Close race and authorization gaps found in the wave 8 security review.

  - OIDC provider authorization codes and refresh tokens, JWT session refresh tokens and passkey challenges are now claimed with one conditional write, so two concurrent redemptions of the same value cannot both succeed (RFC 6749 section 4.1.2, RFC 9700 section 4.14).
  - Org `handleRequest`: an invitation can only be accepted by the user it was sent to, only an owner grants the owner role, changes or removes an owner or deletes the org, and listing invitations needs owner or admin. Accepting an invitation is a single conditional write.
  - `auth.session.cookieName` is honored by the plugin endpoints, headless module handlers, sign out, OAuth and passkey sign in. Before, only the sign in gate read it.
  - The framework integration gate allows a tool call only on a literal `allowed: true`.
  - The audit provenance filter casts to `CHAR` on MySQL, which has no `CAST AS TEXT`.
  - A backdated audit write no longer recreates the pseudonym secret of a shredded period.

## 1.3.0

### Minor Changes

- bf41bbb: Add `theauth dev` (zero-config local first run), a Cloudflare Workers template, an opt-in `adminApi` plugin with an admin MCP server (read-only by default, writes gated by approval), a black-box agent-auth conformance suite, and LangGraph and Mastra approval wrappers.

  Breaking behavior in the gateway: the client `Authorization` and `DPoP` headers are no longer forwarded to the upstream by default. Opt out with `--forward-auth` or `stripAuthHeader: false`. The gateway also gains an MCP mode, a 10 MiB request body limit, a 30 second upstream header timeout, and hop-by-hop and `X-Forwarded-*` header handling. Core gains a browser-safe `@glinr/theauth/browser` entry.

## 1.2.0

### Minor Changes

- 38156ce: Agent accountability, enforced before the action runs.

  `policy.evaluate` now returns `decision: "allow" | "deny" | "escalate"`. A typed `RiskContext` (amount, currency, data class, irreversible) and `risk.tiers` in the engine config map a request to no approval, human approval, or step-up. Pass `{ openApproval: true }` to open the approval request when a decision escalates. `effect` is still the canonical field, and `allowed` is true only for `allow`.

  Delegation now keeps constraints. `delegate()` stores the grant's constraints narrowed against the parent (`requireApproval` is OR-ed, `maxCallsPerHour` takes the smaller value, lists are intersected), and `evaluate` reads delegated permissions the same way `authorize` does. The resolved chain exposes `rootOwnerId` and `path`, and a request that names an owner different from the agent's owner is denied with `POLICY_OWNER_MISMATCH`.

  Audit rows gained `subject_id`, `actor_id`, `policy_version`, `approver_id`, `delegation_chain`, `input_provenance` and `hash_version`, and `result` accepts `"escalated"`. Set `policyVersion` in the engine config to record which policy decided. `input_provenance` is stored as given, nothing fills it in for you.

  Behavior changes to know about:

  - ABAC `requireApproval` now escalates instead of returning a plain deny. `allowed` is still false.
  - `evaluate` writes an audit row on every call, and that row joins the hash chain. A failed write is counted like any other audit failure.
  - Delegation and approval events are now chained, and retention cleanup leaves an `audit.checkpoint` row so verification still passes after old rows are deleted.
  - Chained ids are keyed pseudonyms, so GDPR erasure blanks the raw ids without breaking verification. Rows written before this release (`hash_version` null or 1) get an `audit.erasure` record and verify as erased, not as tampered.
  - `recordAuditEvent` still never throws. Failures are now counted (`getAuditWriteFailures`, `setAuditWriteErrorHandler`, `audit.onAuditError`), and the next successful write is preceded by an `audit.write_failed` row.

- 53a8661: `agent.revoke()` now revokes every active delegation chain where the agent is the source or the target, and the chains downstream of them. It returns the revoked chain ids as `revokedDelegations` and writes one `agent.cascade.revoked` audit row that joins the hash chain.
- 53a8661: Added `guardTool` and `guardTools`, which put the policy engine in front of any agent tool with an `execute` function, with no framework dependency. A denied call throws `ToolDeniedError`, a call that needs a human throws `ToolApprovalRequiredError` with the approval request id and tier, and a failed check throws `ToolGuardFailedError`. The tool never runs in those cases. Pass the `approvalId` option to retry an approved call: the guard hands it to `evaluate`, which spends it once. The `PolicyEngineConfig` type is now exported from the package root.
- 53a8661: Added signed audit checkpoints and portable receipts. `createCheckpoint` builds an RFC 6962 style Merkle tree over the chained audit rows and signs the tree head with Ed25519. `createInclusionProof`, `createConsistencyProof` and `createReceipt` produce proofs that `verifyInclusionProof`, `verifyConsistencyProof` and `verifyReceipt` check offline with only a public key. A receipt reveals the decision fields you pick and keeps the rest as salted commitments. Includes `generateCheckpointKeyPair`, `createEd25519Signer`, and a `CheckpointStore` interface with `createMemoryCheckpointStore`.
- 53a8661: `authorize()` and `policy.evaluate()` now accept an optional `approvalId`. When the matched permission requires approval, the call verifies that the approval request is approved, belongs to the same agent, matches the action and resource exactly, is not expired and was not used, then spends it with a single conditional update and allows the call. Failures are denied with `APPROVAL_NOT_FOUND`, `APPROVAL_NOT_APPROVED`, `APPROVAL_MISMATCH`, `APPROVAL_EXPIRED` or `APPROVAL_ALREADY_USED`. The audit row records `approver_id` and the approval id. A nullable `consumed_at` column is added to the approval requests table automatically.
- 53a8661: Added `resolveActorAgentId` and `allowUnmappedActors` to the MCP config. The live delegation check can now map each actor in a token's `act` chain (and the token subject) to the agent id used in delegation records before it looks up the link, so the built-in `createDbDelegationStore` works when token exchange sets `act.sub` to a user or client id. An actor the mapper returns `undefined` for rejects the token with `INVALID_TOKEN` ("unmapped actor") unless `allowUnmappedActors` is true, and a mapper that throws always rejects. Without a mapper nothing changes. `checkLiveDelegation` now takes an options object as its fourth argument in place of the `now` date.
- 53a8661: MCP: new opt-in `delegationStore` config that re-checks a token's `act` delegation chain against live link records in `validateAccessToken`. A missing, revoked or expired link rejects the token with `INVALID_TOKEN`, so revoking a parent grant no longer leaves tokens minted down the chain valid until `exp`. Adds `createDbDelegationStore(db)` and the `McpDelegationStore` and `McpDelegationLink` types. Default behaviour is unchanged when not configured.
- 53a8661: Add policy shrink: `analyzeUsage` compares an agent's effective permissions (including active delegations) with its recorded decisions, `suggestShrink` proposes a smaller set (with optional, bounded generalization), and `verifyShrink` and `previewPolicyChange` report which recorded decisions would flip for any proposed permission change. Reads audit rows in pages and never changes permissions.
- 53a8661: Added a taint-aware (information flow) tool guard. Tool arguments can carry provenance labels, given through the new `provenance` and `tracker` options of `guardTool`/`guardTools`, through `tainted()` values, or through a `ProvenanceTracker` that registers tool results as `tool_output:<tool>`. A new `policy.taint` config restricts which labels may flow into which tools with `forbid` and `require` rules, per tool or per argument, and either escalates for approval (reusing the single use `approvalId` flow) or denies with `POLICY_TAINT_VIOLATION`. The labels and the verdict are written to the hash chained decision record's `input_provenance` automatically. Behavior with no labels supplied is unchanged. New helpers: `tainted`, `untaint`, `labelsOf`, `deriveLabels`, `matchLabel`, `ProvenanceTracker`.

### Patch Changes

- 53a8661: Delegation constraints now fail closed when a child's argument patterns, IP allowlist or time window do not overlap the parent's. Before, the parent's wider value was kept and the child's restriction was silently dropped. The narrowed result now denies every call. Overnight time windows that are not identical to the other window also deny instead of falling back to the parent's.
- 38156ce: `policy.evaluate` now denies revoked, suspended and expired agents with `POLICY_AGENT_INACTIVE`. Requests that arrive with an agent token were already rejected once the agent was revoked, but `evaluate` takes an agent id directly and never read the agent's status, so a revoked agent could still be allowed by a matching permission. If you gate actions with `evaluate`, upgrade.
- 53a8661: Security fix: the policy engine now fails closed on several constraint edge cases. `maxCallsPerHour: 0` denies every call instead of meaning no limit. IPv4 allowlist parsing rejects octets such as `1abc`. `allowedArgPatterns` checks strings nested in objects and arrays, and an invalid pattern denies instead of throwing. Time windows must be `HH:MM`, support overnight ranges (start after end), and a malformed window denies. `policy.evaluate` denies an agent id with no matching row with `POLICY_AGENT_NOT_FOUND`. A throwing `afterAuthorize` or `onViolation` hook no longer causes an unhandled rejection. Delegation chain limits no longer spread large arrays into `Math.min`.
- 53a8661: Session and audit correctness fixes. Session refresh now creates the replacement before deleting the old session, and a concurrent refresh that loses the race no longer leaves two live sessions. `maxConcurrent` is re-checked after insert, so concurrent sign-ins cannot exceed the cap (a racer that loses is dropped and `create()` throws `MultiSessionLimitError`). A failing audit write no longer makes `authorize()` throw. When the delegated fallback runs, one audit row is written for the final result instead of an orphan row per path. `canonicalJson` rejects reference cycles and serializes BigInt. Rate limit windows are parsed once at construction, a zero window is rejected, and the `client_id` body scan reads at most 8 KB.

## 1.1.2

### Patch Changes

- 7383072: SCIM user deactivation (PUT or PATCH with `active=false`) and DELETE now delete the user's sessions. Previously the user was banned but kept live sessions.

## 1.1.1

### Patch Changes

- First release on the 1.x line. The public API is the one documented in [STABILITY.md](https://github.com/glincker/theauth/blob/main/STABILITY.md) and there are no API changes from the previous 0.x release. From here breaking changes only ship in a major.

## 0.8.0

### Minor Changes

- 2c6f86d: Express, Fastify and NestJS adapters now rate limit requests in three tiers and reject cross-site writes made with a cookie session. New options on every adapter: `rateLimit`, `trustedOrigins` and `csrf`. Both checks are on by default; set `rateLimit: false` or `csrf: false` to opt out.
- 3941782: Adapter rate limit counters use the `rateLimit` secondary storage, so one limit holds across instances when a shared store is configured. `guard.admit` is now async.
- 606693b: Adapter rate limits take `skip` (leave a request out) and `key` (replace the client key) callbacks.
- 292ec38: MCP authorization server: new opt-in grants and client compatibility options. `lenientClients` (optionalResource, dropUnknownScopes, loopbackAnyPort, loopbackAllowLocalhost, pathAudience) relaxes strict request checks for real-world clients and is off by default. `clientCredentials` adds the client_credentials grant for confidential clients, mapped to a principal through `resolvePrincipal`, scope-limited, with no refresh token and optional DPoP binding. `tokenExchange` adds RFC 8693 exchange of access tokens issued by this server with scope narrowing, configured-resource audience changes, a nested `act` claim capped at 3 hops, revocation checks and DPoP binding checks. `jwtBearer` redeems RFC 7523 ID-JAG assertions (`typ: oauth-id-jag+jwt`) from trusted issuers with JWKS fetched through the SSRF-safe fetcher, jti replay protection and a subject mapper. Clients can authenticate with `private_key_jwt` (registered `jwks` or `jwks_uri`, or a Client ID Metadata Document). Client ID Metadata Documents honor Cache-Control max-age within 60 seconds to 24 hours and keep a short negative cache for failed fetches. Fixes the step-up `upgrade_url`, which pointed at `/authorize` instead of `/mcp/authorize`. Metadata advertises the enabled grants and `private_key_jwt`. The client_credentials grant, previously rejected, now parses and returns `unsupported_grant_type` unless enabled.
- 292ec38: `/mcp/revoke` accepts `private_key_jwt` client authentication (`client_assertion` and `client_assertion_type`), reusing the token endpoint verifier. The assertion `aud` must be the revocation endpoint or the issuer, each `jti` is single use across the token and revocation endpoints, and an assertion cannot be combined with a client secret. `client_secret_basic`, `client_secret_post` and public clients are unchanged. Discovery now lists `private_key_jwt` and the signing algorithms under `revocation_endpoint_auth_methods_supported` and `revocation_endpoint_auth_signing_alg_values_supported`.
- bf91c2f: Native app social sign-in. The oauth plugin takes `mobile: { redirectUris }` and adds a PKCE code exchange at `POST /auth/oauth/mobile/exchange`, so a session token is never placed in a redirect URL. `@glinr/theauth-expo` gains `signInWithProvider` and `useSocialSignIn`, `createSecureStoreStorage`, and an `appState` option that refreshes the session when the app returns to the foreground. The oauth plugin now also creates the `theauth_one_time_tokens` table.
- 87e24ea: Working sign-in providers for Linear, Kick, Vercel, PayPal and Kakao: `createLinearProvider`, `createKickProvider`, `createVercelProvider`, `createPaypalProvider` (with `sandbox`) and `createKakaoProvider`. The older `linearProvider`, `kickProvider`, `vercelProvider`, `paypalProvider` and `kakaoProvider` presets read the wrong userinfo shape or the wrong endpoints and are unchanged. `genericOIDC` gains optional `scopeSeparator`, `defaultScopes`, `userinfoMethod`, `userinfoBody`, `authorizationParams`, `tokenAuth` (`"basic"`) and `pkce`, and `mapProfile` may return `emailVerified`. Existing configs behave as before.
- 292ec38: Social sign-in token API. The OAuth module gains `getAccessToken({ userId, provider })` (single flight refresh on expiry, rotated tokens persisted), `listAccounts(userId)` and `unlinkAccount(userId, provider)` with a last-credential guard, plus typed `OAuthTokenError` codes (`no_account`, `no_refresh_token`, `refresh_failed`, `revoked`, `decrypt_failed`, `last_credential`). The plugin adds `GET /auth/oauth/accounts` and `DELETE /auth/oauth/accounts/:provider` and exposes the module as `pluginContext.oauth`. Optional `tokenEncryption` seals tokens at rest with the token vault AES-256-GCM envelope; legacy plaintext rows stay readable and are re-encrypted on their next write. Built-in providers implement `refreshTokens`. Stateless sessions now share one `refreshAccessToken` call between concurrent `getAccessToken` calls.
- fdb0d52: OpenID Shared Signals Framework 1.0 with CAEP and RISC. New `sharedSignals()` plugin (also at `@glinr/theauth/signals`) mounts an SSF transmitter (stream management, status, subjects, verification, push per RFC 8935 with retry and SSRF-safe URLs, poll per RFC 8936) and a receiver that verifies Security Event Tokens (RFC 8417) and revokes local sessions on session-revoked, sessions-revoked and account-disabled. Emission is opt in through new `onPasswordChanged` (password reset), `onChange` (TOTP) and `onCredentialChange` (passkey) callbacks plus the existing session `onRevoke` and admin `onAdminAction`. Adds the `theauth_ssf_*` tables when the plugin is present.
- 292ec38: Sign-in gate covers every session-issuing path. `SignInMethod` gains `phone`, `email_otp`, `one_tap`, `siwe` and `device` (exported as `SIGN_IN_METHODS`). Phone verify, email OTP verify, Google One Tap and the device-auth plugin now call the gate before issuing a session and answer with `SignInGateError` or the standard challenge response. The `require2faFor` default is unchanged (password, social, magic_link), so the new methods only ask for a second factor when you list them; a forced password change applies to them as it does to the other methods. `createPhoneAuthModule`, `createEmailOtpModule` and `createOneTapModule` take an optional trailing `signInGate`, and `verifyCode` accepts `{ request }` for trusted-device cookies. `createDeviceAuthModule`'s `issueToken` may throw `SignInGateError` to answer the token poll with a challenge. SIWE only verifies a signature and issues no session, so it has no call site yet; the `siwe` method name is reserved for apps that mint a session from it.

  New `createPasskeyTwoFactorFactor(passkey)` makes a registered passkey usable as a second factor (`signInGate.factors`). The code sent to `/auth/sign-in/two-factor` is the WebAuthn assertion as JSON or base64url JSON, verified by the passkey module and required to belong to the challenged user.

  Stateless sessions accept `signInGate`, `gateMethod` and a per call `{ request, method }` context. `createSession` then fails with `TWO_FACTOR_REQUIRED` or `PASSWORD_RESET_REQUIRED` and the challenge in `error.details`, issuing no cookies.

- 292ec38: Central sign-in gate. Every session-issuing path (username, magic link, passkey, and the OAuth callback via `ctx.signInGate`) now asks one gate whether a session may be issued. A forced password change returns a signed challenge instead of a hard block, and users with TOTP enabled get a `two_factor_required` challenge for the methods in `signInGate.require2faFor` (default when `signInGate` is set: password, social, magic_link). New routes `POST /auth/sign-in/two-factor` and `POST /auth/sign-in/password-change` finish the flow. Optional trusted devices (`signInGate.trustedDevice.enabled`, default off) skip 2FA through a random device cookie, are listed and revoked at `/auth/trusted-devices`, and are revoked on any password change. `SignInGateError` is thrown by `username.signIn` and `magicLink.verify`, with the existing "Password reset required" message kept.

  Session limits. `auth.session.maxConcurrent` with `onLimit: "evict-oldest" | "reject"` caps concurrent sessions per user inside `sessionManager.create`. `auth.session.onRevoke` reports revoked sessions.

  OIDC logout. `createOidcProviderModule({ logout })` adds an RP-initiated `end_session_endpoint` (id*token_hint and post_logout_redirect_uri allowlist validation), advertises `end_session_endpoint` and `backchannel_logout*\*`in discovery, adds`sid`to ID tokens, and fans out back-channel logout tokens to each client's`backchannel_logout_uri`on logout and on session revoke. Failures never block local logout.`createBackChannelLogoutReceiver`can now revoke local sessions by sid or sub through a session manager or an injected`revokeSessions`callback. Adds two tables,`theauth_oidc_logout_clients`and`theauth_oidc_sessions`.

- 842e1ec: `createStatelessSessions` now refuses token cookies written before the identity binding by default (`acceptLegacyTokenCookies` was `true`). Set it to `true` for one cookie lifetime when upgrading with live sessions; otherwise affected users sign in again once.
- 20d865b: Typed plugin endpoints. `defineEndpoint` validates params, query and body with zod and exposes the shapes through `ApiOf`; `createEndpointClient` in the client package calls routes by `"METHOD /path"` key with inferred input and result types.

### Patch Changes

- d303a84: Share the rate limit and cross-site refusal writer between the Express and NestJS adapters.
- 988b17d: The remaining adapters now apply the same rate limits and cross-site write check as Express, Fastify and NestJS (`rateLimit`, `trustedOrigins`, `csrf`). The strict tier also matches when the adapter is mounted under a path prefix.
- f54c346: Trim trailing slashes with a scan instead of `replace(/\/+$/, "")`, which is quadratic on a long run of slashes (federation discovery URL, self-hosted provider presets, CLI token cache key). Match whitespace before the `>` in the codemod's closing script tag. Repeat the reserved attribute name check inline at each SCIM PATCH property write.
- 6b0eb03: Require `drizzle-orm` 0.45.2 or newer. Earlier versions do not escape SQL identifiers correctly, which allows SQL injection when an identifier is built from untrusted input (GHSA advisory for drizzle-orm below 0.45.2). The ranges in the create-theauth-app template and the examples are bumped too.
- 292ec38: Security: the stateless session token cookie is now bound to the identity cookie. A token cookie sealed under the same secret for another user, or for an older session of the same user, no longer decrypts (AES-GCM additional data over `sub` and `issuedAt`). New cookies use a `v2:` format. Legacy cookies are still read for one release: they are re-sealed in the new format on the next `getAccessToken`, and `onDeprecation` is called once per read so you can log it. Set `acceptLegacyTokenCookies: false` once old cookies have expired (after `maxAge`) to close the window; the default stays `true`.

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
