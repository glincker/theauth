# Routes the client still wants from theauth-go

Everything below is not available on the Go router as of the commit in `routes.manifest.json`.

- `POST /auth/webauthn/login/begin` with a conditional-UI hint, so `mediation: "conditional"` autofill can be offered.
- Logout while `pending_2fa`: `DELETE /auth/sessions/current` requires full auth, so an abandoned MFA step cannot be cancelled.
- A JSON error body on the remaining handlers that still call `http.Error` (TOTP regenerate, WebAuthn rename and list); the client maps those to `HTTP_ERROR`.
- `/auth/totp` without the trailing slash: the routes are mounted at `/auth/totp/`, and chi 404s the bare path.
