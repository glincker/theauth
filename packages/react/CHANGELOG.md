# @glinr/theauth-react

## 0.7.0

### Minor Changes

- 9df9f17: Add a typed theauth-go client (`createTheAuthGoClient`: login with MFA result, logout, session, passkeys, TOTP) and TanStack Query hooks at `@glinr/theauth-react/query`.
- 32dd176: Cover the new theauth-go routes: sessions list and revoke, password change, step-up, API tokens, device grant with a polling helper, bootstrap status and setup token, TOTP status and recovery-code regeneration, passkey rename, plus throttle and recent-auth error helpers. Matching hooks at `@glinr/theauth-react/query` and a route manifest drift test.
- 1cd4db9: Agent tokens: `GoApiToken` gains `kind`, `agentName` and `delegatedBy`, and `apiTokens.mint` accepts `kind` and `agentName`. `useApiTokens` takes a `kind` filter and `useAgentTokens` mints, lists and revokes agent tokens. New `@glinr/theauth-ui-headless` package with unstyled `SessionList`, `ApiTokenList`, `MintTokenForm`, `DeviceApproval`, `StepUpDialog` and `useStepUpRetry`.
- 713c698: Bearer-mode client and agent self-service. `createTheAuthGoClient` takes `getToken`, which sets `Authorization` and omits credentials. `apiTokens.current()` and `apiTokens.revokeCurrent()` call the bearer-only `/auth/tokens/current`; a cookie session gets `auth.bearer_required` (`isBearerRequired`). New `agents` (list, register, revoke) and `delegations` (list, grant, revoke) client methods over `/auth/account/*`, with `useCurrentToken`, `useAgents`, `useDelegations` hooks and unstyled `AgentList` and `AgentRegisterForm` components.
- 0fa5b1e: Remove the legacy KavachOS naming. The deprecated `Kavach*` and `createKavach` exports are gone: use `TheAuth*` and `createTheAuth`. Environment variables are now `THEAUTH_*`, webhook headers `X-TheAuth-*`, cookies and the default API route use `theauth`, and database tables are `theauth_*` (existing `kavach_*` tables are renamed in place by `createTables`, no data is lost). `Auth*` aliases remain deprecated.

### Patch Changes

- Updated dependencies [9df9f17]
- Updated dependencies [32dd176]
- Updated dependencies [1cd4db9]
- Updated dependencies [713c698]
- Updated dependencies [0fa5b1e]
  - @glinr/theauth-client@0.3.0

## 0.6.0

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

## 0.2.0

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
