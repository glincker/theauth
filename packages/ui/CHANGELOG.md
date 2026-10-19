# @glinr/theauth-ui

## 0.4.0

### Minor Changes

- b7fbe38: Point the UI, Expo, Electron and dashboard callers at routes the core handler serves. Before, these calls answered 404 against a TypeScript server.

  - `@glinr/theauth-ui`: `TwoFactorVerify` posts `{ code }` to `/auth/2fa/verify` (a backup code goes in the same `code` field) and reads the core's `{ error: "..." }` body. `OAuthButtons` navigates to `/auth/oauth/authorize/:provider`, and the server builds the callback URL itself.
  - `@glinr/theauth-expo` and `@glinr/theauth-electron`: sign-in and sign-up now call `/auth/username/sign-in` and `/auth/username/sign-up` with a `username` field, the session check is `GET /auth/session` and sign-out is `POST /auth/sign-out`. New options `signInPath`, `signUpPath` and `identifierField` point them at your own email route (for example `/auth/sign-in` with `identifierField: "email"` from `@glinr/theauth-email`). Responses read the core shape `{ user, session: { token, expiresAt } }`, and the older `{ data }` envelope still works. A 5xx on the session check no longer signs the user out.
  - `@glinr/theauth-electron`: `openOAuthWindow` opens `/auth/oauth/authorize/:provider` and waits for the core callback to redirect back before it reports success, instead of closing the window on the provider redirect that carries `code=`.
  - `@glinr/theauth-dashboard`: revoking an agent uses `DELETE /agents/:id`, and an agent's permissions come from `GET /agents/:id`. The Users, Permissions, Settings and MCP Servers pages call routes only the CLI dev server serves. Against a server without them the pages now show a "does not serve" message.

  Upgrade note: if your Expo or Electron app relied on `/sign-in/email` and `/sign-up/email`, set `signInPath`, `signUpPath` and `identifierField` to the routes your server serves.

## 0.3.0

### Minor Changes

- 640cd9f: Browser passkey client for the TypeScript server. `createPasskeyClient` runs registration and sign-in against the passkey plugin routes, with conditional UI (autofill) support, and `SignIn` takes a `passkeyClient` prop for a passkey button and autofill suggestions.
- 3a041af: Accessibility pass on the default components. Errors are announced (`role="alert"`), field errors are linked to their input with `aria-describedby` and `aria-invalid`, the loading button sets `aria-busy`, the verification code digits and backup code input have accessible names inside a labelled group, and the auth card is a region named by its title. The default slots now live in one shared module instead of four copies.

## 0.2.0

### Minor Changes

- 0fa5b1e: Remove the legacy KavachOS naming. The deprecated `Kavach*` and `createKavach` exports are gone: use `TheAuth*` and `createTheAuth`. Environment variables are now `THEAUTH_*`, webhook headers `X-TheAuth-*`, cookies and the default API route use `theauth`, and database tables are `theauth_*` (existing `kavach_*` tables are renamed in place by `createTables`, no data is lost). `Auth*` aliases remain deprecated.

## 0.1.0

### Minor Changes

- 94804ec: Launch release: promote core and primary client-facing packages to the 0.1 line.

  Highlights:

  - Stabilize package exports and build artifacts for launch.
  - Ship improved CLI version handling and launch docs.
  - Keep adapters/plugins/dashboard on existing release tracks for a separate coordinated versioning pass.
