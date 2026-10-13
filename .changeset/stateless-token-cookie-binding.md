---
"@glinr/theauth": patch
---

Security: the stateless session token cookie is now bound to the identity cookie. A token cookie sealed under the same secret for another user, or for an older session of the same user, no longer decrypts (AES-GCM additional data over `sub` and `issuedAt`). New cookies use a `v2:` format. Legacy cookies are still read for one release: they are re-sealed in the new format on the next `getAccessToken`, and `onDeprecation` is called once per read so you can log it. Set `acceptLegacyTokenCookies: false` once old cookies have expired (after `maxAge`) to close the window; the default stays `true`.
