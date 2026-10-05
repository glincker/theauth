# Routes the client wants from theauth-go

The Go router only exposes these end-user routes today, so the client covers them and nothing more. Wishlist for the Go side:

- `GET /auth/sessions`: list the caller's own sessions (id, userAgent, ip, createdAt, current flag). `/admin/v1/sessions` exists but is permission-gated and currently returns an empty list.
- `DELETE /auth/sessions/{id}` and `DELETE /auth/sessions` (all others): revoke one or all other sessions for the caller. Only `DELETE /auth/sessions/current` exists.
- `GET /auth/totp` (status): whether TOTP is enrolled and how many recovery codes remain. Needed to render a 2FA settings card.
- `POST /auth/totp/recovery-codes`: regenerate recovery codes. They are only returned once, at `enroll/finish`.
- Passkey rename: `PATCH /auth/webauthn/credentials/{id}` to rename a passkey.
- `POST /auth/webauthn/login/begin` with a conditional-UI hint, so `mediation: "conditional"` autofill can be offered.
- Step-up: a stable `step_up_required` error code and a fresh-auth window.
- A JSON error body on every failure. Several handlers still reply with plain text via `http.Error`; the client maps those to `HTTP_ERROR`.
- `DELETE /auth/totp/` is mounted with a trailing slash; `/auth/totp` returns 404 on chi without a redirect.
- Personal API tokens and RFC 8628 device-code verification: no user-facing routes found.
- Logout while `pending_2fa`: `DELETE /auth/sessions/current` requires full auth, so an abandoned MFA step cannot be cancelled.
