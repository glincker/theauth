# @glinr/theauth-electron

## 0.4.0

### Minor Changes

- b7fbe38: Point the UI, Expo, Electron and dashboard callers at routes the core handler serves. Before, these calls answered 404 against a TypeScript server.

  - `@glinr/theauth-ui`: `TwoFactorVerify` posts `{ code }` to `/auth/2fa/verify` (a backup code goes in the same `code` field) and reads the core's `{ error: "..." }` body. `OAuthButtons` navigates to `/auth/oauth/authorize/:provider`, and the server builds the callback URL itself.
  - `@glinr/theauth-expo` and `@glinr/theauth-electron`: sign-in and sign-up now call `/auth/username/sign-in` and `/auth/username/sign-up` with a `username` field, the session check is `GET /auth/session` and sign-out is `POST /auth/sign-out`. New options `signInPath`, `signUpPath` and `identifierField` point them at your own email route (for example `/auth/sign-in` with `identifierField: "email"` from `@glinr/theauth-email`). Responses read the core shape `{ user, session: { token, expiresAt } }`, and the older `{ data }` envelope still works. A 5xx on the session check no longer signs the user out.
  - `@glinr/theauth-electron`: `openOAuthWindow` opens `/auth/oauth/authorize/:provider` and waits for the core callback to redirect back before it reports success, instead of closing the window on the provider redirect that carries `code=`.
  - `@glinr/theauth-dashboard`: revoking an agent uses `DELETE /agents/:id`, and an agent's permissions come from `GET /agents/:id`. The Users, Permissions, Settings and MCP Servers pages call routes only the CLI dev server serves. Against a server without them the pages now show a "does not serve" message.

  Upgrade note: if your Expo or Electron app relied on `/sign-in/email` and `/sign-up/email`, set `signInPath`, `signUpPath` and `identifierField` to the routes your server serves.

- 6bdec47: Email and password in core. A new top-level `emailPassword` config key stores a real email in `users.email` and serves `POST /auth/email/sign-up`, `/sign-in`, `/verify`, `/resend-verification`, `/forgot-password`, `/reset-password` and `/change-password` from `createTheAuthHandler`. It reuses the username credential table, hashing, lockout and sign-in gate, and issues ordinary core sessions with the session cookie. Verification is on by default (it needs `emailVerification`): sign-up creates no session, sign-in answers `EMAIL_NOT_VERIFIED` only after the password checks out, and a sign-up for a taken address answers like a new one and never attaches a password to the existing user. A completed password reset marks the address verified.

  Client bindings: `emailPassword: true` on the session store, React `managed`, the Vue plugin, the Svelte client, the Expo provider config and the Electron provider points them at the new routes. Sign-up now reports `verificationRequired`, failed results carry the server `code`, and the store, React (`useEmailPassword`), Vue and Svelte expose `verifyEmail`, `resendVerification`, `requestPasswordReset` and `resetPassword`. React `signUp` resolves to `data: { verificationRequired }` instead of `data: undefined`. `@glinr/theauth-react` also splits `context.tsx` into smaller files with no behavior change.

  Fixes: `emailVerification` alone no longer fails with "no such table" (the one-time token table is now created for it). `@glinr/theauth-email` is deprecated: its sign-in token is not a core session (`GET /auth/session` answers 401, no cookie is set) and its sign-up returned a session token before verification. Use `emailPassword`.

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
