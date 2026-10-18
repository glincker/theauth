---
"@glinr/theauth": minor
---

Self service API keys are capped to the caller. `POST /auth/api-keys` (the `apiKeys` plugin and the `apiKeys.handleRequest` module handler) refuses with 403 `permissions_not_grantable` when the key asks for a permission the signed in user does not hold. New `ApiKeyManagerConfig` fields: `grantablePermissions(userId)` returns the user's own permissions (`*` and `ns:*` patterns cover narrower ones) and `adminOverride(userId)` lifts the cap for named users. With neither set, a self service request may only ask for an empty permission list. `theauth.apiKeys.create()` and `trustedServerUse` callers are not capped. Malformed `permissions` values now answer 400.

OIDC provider refresh token reuse now revokes the whole token family (RFC 9700 section 4.14.2). Migration `0012-oidc-refresh-family` adds a nullable `family_id` to `theauth_oidc_refresh_tokens` (OIDC provider enabled). Tokens issued before it fall back to revoking every refresh token of the same user and client on reuse. Run `theauth db up`.

The admin API routes for audit events, delegations, user disable, sessions and revocations are now in the generated OpenAPI document, and the admin approval routes are documented as returning bare JSON, which is what they send. The drift test checks every admin route the plugin registers. The decision code lists in the Python and Go clients are generated from `DECISION_CODES` by `scripts/generate-openapi.ts`, with a drift test.
