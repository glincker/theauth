# @glinr/theauth-vue

## 0.4.0

### Minor Changes

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

- Updated dependencies [b7fbe38]
- Updated dependencies [b7fbe38]
- Updated dependencies [6bdec47]
- Updated dependencies [6bdec47]
  - @glinr/theauth-client@1.2.0

## 0.3.0

### Minor Changes

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
