---
"@glinr/theauth": minor
---

Secret rotation for webhook signing, the session cookie cache and stateless session cookies. New `SecretRing` (and `createSecretRing`) in the crypto module: `secret` can now be a string or `[current, ...previous]`, entries may be `{ id, secret }`. The first secret signs and encrypts, every secret verifies and decrypts, so changing a secret no longer invalidates everything already issued.

- Webhooks: endpoint `secret` accepts the list form, deliveries add an optional `X-TheAuth-Key-Id` header when the current key has an id, and `verify` accepts a list plus an optional `keyId`. Plain string secrets behave as before.
- `createSessionCookieCache` and `createStatelessSessions`: `secret: string | string[]`. The key id, when set, is appended to the cookie value. The string form is unchanged.
- Construction rejects empty and duplicate secrets and secrets under 32 bytes (a plain webhook string keeps its old no minimum rule). Secrets are never logged or included in error messages.
