---
"@glinr/theauth": major
---

Security fixes from the HTTP handler review. Some of these fix bugs that are in published releases (1.2.0 and earlier), others fix unreleased 2.0 work only.

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
