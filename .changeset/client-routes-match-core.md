---
"@glinr/theauth-ui": minor
"@glinr/theauth-expo": minor
"@glinr/theauth-electron": minor
"@glinr/theauth-dashboard": minor
---

Point the UI, Expo, Electron and dashboard callers at routes the core handler serves. Before, these calls answered 404 against a TypeScript server.

- `@glinr/theauth-ui`: `TwoFactorVerify` posts `{ code }` to `/auth/2fa/verify` (a backup code goes in the same `code` field) and reads the core's `{ error: "..." }` body. `OAuthButtons` navigates to `/auth/oauth/authorize/:provider`, and the server builds the callback URL itself.
- `@glinr/theauth-expo` and `@glinr/theauth-electron`: sign-in and sign-up now call `/auth/username/sign-in` and `/auth/username/sign-up` with a `username` field, the session check is `GET /auth/session` and sign-out is `POST /auth/sign-out`. New options `signInPath`, `signUpPath` and `identifierField` point them at your own email route (for example `/auth/sign-in` with `identifierField: "email"` from `@glinr/theauth-email`). Responses read the core shape `{ user, session: { token, expiresAt } }`, and the older `{ data }` envelope still works. A 5xx on the session check no longer signs the user out.
- `@glinr/theauth-electron`: `openOAuthWindow` opens `/auth/oauth/authorize/:provider` and waits for the core callback to redirect back before it reports success, instead of closing the window on the provider redirect that carries `code=`.
- `@glinr/theauth-dashboard`: revoking an agent uses `DELETE /agents/:id`, and an agent's permissions come from `GET /agents/:id`. The Users, Permissions, Settings and MCP Servers pages call routes only the CLI dev server serves. Against a server without them the pages now show a "does not serve" message.

Upgrade note: if your Expo or Electron app relied on `/sign-in/email` and `/sign-up/email`, set `signInPath`, `signUpPath` and `identifierField` to the routes your server serves.
