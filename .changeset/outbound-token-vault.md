---
"@glinr/theauth": minor
---

Outbound token vault. New `tokenVault()` plugin and `createTokenVault()` store third-party OAuth connections per user, encrypted with AES-256-GCM (key ids for rotation), and hand agents short-lived access tokens via `vault.getAccessToken({ agentId, userId, provider, scopes })`.

- Each read checks the agent's `vault:<provider>` `use` permission (own or delegated), the user's consent for those scopes, and the connection's scopes. Scopes can only narrow. Every read is written to the audit log.
- Refreshes are single flight (in process and through `secondaryStorage`, new `tokenVault` feature key).
- Connect flow endpoints under `/auth/vault/*` use PKCE S256, single-use state and bind the callback to the signed-in user.
- `theauth.delegation.revoke()` now also revokes vault consents tied to that chain when the plugin is installed.
- Additive: new `theauth_vault_connections` and `theauth_vault_consents` tables, created only when the plugin is present.
