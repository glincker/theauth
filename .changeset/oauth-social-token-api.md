---
"@glinr/theauth": minor
---

Social sign-in token API. The OAuth module gains `getAccessToken({ userId, provider })` (single flight refresh on expiry, rotated tokens persisted), `listAccounts(userId)` and `unlinkAccount(userId, provider)` with a last-credential guard, plus typed `OAuthTokenError` codes (`no_account`, `no_refresh_token`, `refresh_failed`, `revoked`, `decrypt_failed`, `last_credential`). The plugin adds `GET /auth/oauth/accounts` and `DELETE /auth/oauth/accounts/:provider` and exposes the module as `pluginContext.oauth`. Optional `tokenEncryption` seals tokens at rest with the token vault AES-256-GCM envelope; legacy plaintext rows stay readable and are re-encrypted on their next write. Built-in providers implement `refreshTokens`. Stateless sessions now share one `refreshAccessToken` call between concurrent `getAccessToken` calls.
