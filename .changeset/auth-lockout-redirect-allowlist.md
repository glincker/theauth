---
"@glinr/theauth": major
---

Password lockout, fail closed options and a return URL allow list.

Visible default change (the reason for the major bump): username sign-in now locks repeated failures. 10 failed attempts for one username inside 15 minutes lock it for 15 minutes (doubling per repeat, capped at 1 hour), and 3 failures from one IP for one username start a growing delay for that IP. A locked sign-in answers `429` with `Retry-After` and code `SIGN_IN_LOCKED`, and `signIn` throws `LoginLockedError`. Unknown usernames lock identically, so responses do not reveal which accounts exist. Set `username: { lockout: false }` or `THEAUTH_LOGIN_LOCKOUT_DISABLED=true` to keep the old behavior, and tune with `username.lockout` or the `THEAUTH_LOGIN_*` variables. New: `theauth.username.unlockAccount(name)`, the `onLockout` hook and `username.trustedProxy`.

Redirects: `createRedirectChain` now refuses off-site targets. A chain path that is protocol-relative, uses backslashes or control characters, or is an encoded variant of those now comes back as `defaultPath`. New: `redirects.sanitize()`, `allowedOrigins`, and `resolveRedirectTarget` / `safeRedirectTarget` in `@glinr/theauth/redirect`. OAuth modules accept `allowedRedirectUris` (off unless set).

Fail closed (all additive, default stays fail open): `rateLimit.failClosed` for the adapters and handler, `failClosed` on the `rateLimit()` plugin, and `hibp.failClosed` answer `503` or `HibpApiError` when the backing store or API errors. While a limiter fails open it logs a startup warning through the configured logger.
