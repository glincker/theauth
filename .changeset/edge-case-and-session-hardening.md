---
"@glinr/theauth": minor
"@glinr/theauth-express": patch
"@glinr/theauth-nestjs": patch
"@glinr/theauth-nuxt": patch
"@glinr/theauth-astro": patch
"@glinr/theauth-sveltekit": patch
---

Edge case hardening and opt-in session features.

- Security: single-use credentials (magic links, email OTP attempts and codes, one-time tokens, OAuth state, SIWE nonces) are claimed atomically, so concurrent requests cannot redeem the same one twice.
- Security: the OAuth plugin links a provider login to an existing account by email only when the provider and the local account are both verified. Otherwise it returns 409. `linkAccount` refuses to move a provider account to a different user. New accounts store `emailVerified` from the provider instead of always true.
- Security: `withRateLimit` and the OAuth proxy use the trusted proxy rules and ignore `x-forwarded-for` and `x-real-ip` by default. Behind a proxy, set `trustedProxy`.
- Emails are normalized in one place across all email flows.
- Express, NestJS and Nuxt adapters send each `Set-Cookie` as its own header. Express and NestJS plugin routes honor the mount prefix. Astro, Nuxt and SvelteKit dispatchers now serve plugin endpoints.
- New and opt-in: session cookie cache, refresh token `reuseGracePeriod`, `allowedHosts` per-request base URL, `createStatelessSessions`, OIDC back-channel and RP-initiated logout helpers, shared SIWE nonce `storage`.
