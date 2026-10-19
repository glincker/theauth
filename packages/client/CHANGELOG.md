# @glinr/theauth-client

## 1.2.0

### Minor Changes

- b7fbe38: Add `createSessionStore`, a framework-neutral session store (subscribe, sign in, sign up, sign out, injected storage), and `createSolidAuth`, which wraps it as Solid accessors without depending on solid-js.
- b7fbe38: Session refetch, SSR hydration and real server calls in the client bindings.

  Added: `refetch` options (window focus and tab visibility, reconnect, interval) and `hydrateSession(initial)` on `createSessionStore`, wired through the React provider (`managed` prop, `external.refetch`, `external.initialUser`), the Vue plugin, the Svelte client and the Solid helper. Triggers run only while something is subscribed, do nothing without a `window`, share one request across overlapping refreshes, are cancelable (`startAutoRefresh` returns `stop`, `destroy()` aborts), and never log or echo tokens.

  Fixed: the Vue, Svelte and React managed bindings only read `localStorage` and never asked the server. They now confirm the session with `GET /auth/session`, and `signOut` calls `POST /auth/sign-out` after clearing local state, so the session is revoked server side. They also called `/auth/sign-in` and `/auth/sign-up`, which the core never served. The default routes are now `/auth/username/sign-in` and `/auth/username/sign-up` and the first argument is sent as `username`. Error bodies of the form `{ error: "text" }` are now read. External React mode keeps the current user when a refetch hits a network error.

  Upgrade notes:

  - `SessionStore.refresh()` now returns a promise and `SessionStore.signOut()` returns `Promise<StoreActionResult>`.
  - If you served your own `/auth/sign-in` or `/auth/sign-up` routes for these bindings, set `signInPath`, `signUpPath` and `identifierField` (React: `managed`; Vue and Svelte: the plugin or client options).
  - `@glinr/theauth-vue` and `@glinr/theauth-svelte` now depend on `@glinr/theauth-client`.

- 6bdec47: Email and password in core. A new top-level `emailPassword` config key stores a real email in `users.email` and serves `POST /auth/email/sign-up`, `/sign-in`, `/verify`, `/resend-verification`, `/forgot-password`, `/reset-password` and `/change-password` from `createTheAuthHandler`. It reuses the username credential table, hashing, lockout and sign-in gate, and issues ordinary core sessions with the session cookie. Verification is on by default (it needs `emailVerification`): sign-up creates no session, sign-in answers `EMAIL_NOT_VERIFIED` only after the password checks out, and a sign-up for a taken address answers like a new one and never attaches a password to the existing user. A completed password reset marks the address verified.

  Client bindings: `emailPassword: true` on the session store, React `managed`, the Vue plugin, the Svelte client, the Expo provider config and the Electron provider points them at the new routes. Sign-up now reports `verificationRequired`, failed results carry the server `code`, and the store, React (`useEmailPassword`), Vue and Svelte expose `verifyEmail`, `resendVerification`, `requestPasswordReset` and `resetPassword`. React `signUp` resolves to `data: { verificationRequired }` instead of `data: undefined`. `@glinr/theauth-react` also splits `context.tsx` into smaller files with no behavior change.

  Fixes: `emailVerification` alone no longer fails with "no such table" (the one-time token table is now created for it). `@glinr/theauth-email` is deprecated: its sign-in token is not a core session (`GET /auth/session` answers 401, no cookie is set) and its sign-up returned a session token before verification. Use `emailPassword`.

### Patch Changes

- 6bdec47: The session store no longer needs `AbortController`: runtimes that have `fetch` but not `AbortController` (Lynx's PrimJS) can refresh the session, and a late answer is still dropped. New Lynx page with the runtime needs and a storage recipe, checked against the Lynx docs and a stripped runtime, not on a device.

## 1.1.1

### Patch Changes

- First release on the 1.x line. The public API is the one documented in [STABILITY.md](https://github.com/glincker/theauth/blob/main/STABILITY.md) and there are no API changes from the previous 0.x release. From here breaking changes only ship in a major.

## 0.4.0

### Minor Changes

- 292ec38: Add `createDPoPProver` and `createDPoPClient`: an edge safe RFC 9449 helper that builds ES256 DPoP proofs (htm, normalized htu, iat, jti, ath), caches the server nonce per origin, retries once on `use_dpop_nonce`, and exposes a `fetch` wrapper and the JWK thumbprint.
- 640cd9f: Browser passkey client for the TypeScript server. `createPasskeyClient` runs registration and sign-in against the passkey plugin routes, with conditional UI (autofill) support, and `SignIn` takes a `passkeyClient` prop for a passkey button and autofill suggestions.
- 20d865b: Typed plugin endpoints. `defineEndpoint` validates params, query and body with zod and exposes the shapes through `ApiOf`; `createEndpointClient` in the client package calls routes by `"METHOD /path"` key with inferred input and result types.

## 0.3.0

### Minor Changes

- 9df9f17: Add a typed theauth-go client (`createTheAuthGoClient`: login with MFA result, logout, session, passkeys, TOTP) and TanStack Query hooks at `@glinr/theauth-react/query`.
- 32dd176: Cover the new theauth-go routes: sessions list and revoke, password change, step-up, API tokens, device grant with a polling helper, bootstrap status and setup token, TOTP status and recovery-code regeneration, passkey rename, plus throttle and recent-auth error helpers. Matching hooks at `@glinr/theauth-react/query` and a route manifest drift test.
- 1cd4db9: Agent tokens: `GoApiToken` gains `kind`, `agentName` and `delegatedBy`, and `apiTokens.mint` accepts `kind` and `agentName`. `useApiTokens` takes a `kind` filter and `useAgentTokens` mints, lists and revokes agent tokens. New `@glinr/theauth-ui-headless` package with unstyled `SessionList`, `ApiTokenList`, `MintTokenForm`, `DeviceApproval`, `StepUpDialog` and `useStepUpRetry`.
- 713c698: Bearer-mode client and agent self-service. `createTheAuthGoClient` takes `getToken`, which sets `Authorization` and omits credentials. `apiTokens.current()` and `apiTokens.revokeCurrent()` call the bearer-only `/auth/tokens/current`; a cookie session gets `auth.bearer_required` (`isBearerRequired`). New `agents` (list, register, revoke) and `delegations` (list, grant, revoke) client methods over `/auth/account/*`, with `useCurrentToken`, `useAgents`, `useDelegations` hooks and unstyled `AgentList` and `AgentRegisterForm` components.
- 0fa5b1e: Remove the legacy KavachOS naming. The deprecated `Kavach*` and `createKavach` exports are gone: use `TheAuth*` and `createTheAuth`. Environment variables are now `THEAUTH_*`, webhook headers `X-TheAuth-*`, cookies and the default API route use `theauth`, and database tables are `theauth_*` (existing `kavach_*` tables are renamed in place by `createTables`, no data is lost). `Auth*` aliases remain deprecated.

## 0.2.0

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

## 0.1.0

### Minor Changes

- 94804ec: Launch release: promote core and primary client-facing packages to the 0.1 line.

  Highlights:

  - Stabilize package exports and build artifacts for launch.
  - Ship improved CLI version handling and launch docs.
  - Keep adapters/plugins/dashboard on existing release tracks for a separate coordinated versioning pass.
