---
"@glinr/theauth": major
---

Cookies are now `Secure` by default on every runtime, and password hashing is stronger.

Breaking: the `Secure` default no longer reads `NODE_ENV`. It was off whenever `NODE_ENV` was unset (Cloudflare Workers, Deno, Bun). It is now on unless you pass `secure: false`, or pass a `request` for plain `http://localhost`, `127.0.0.1` or `[::1]`, where it turns off for local development. https URLs and trusted proxy `x-forwarded-proto` headers (`trustProxy`) keep it on. Chrome and Firefox accept `Secure` cookies on localhost; for plain-HTTP setups elsewhere pass `cookieOptions.secure: false`.

Cookie serialization is centralized in `serializeCookie` (session manager, cookie cache, refresh, plugins and the redirect chain all use it). New `resolveCookieSecure(request, { trustProxy })`. `__Host-` and `__Secure-` prefixes are validated and invalid combinations throw, as do `Partitioned` or `SameSite=None` without `Secure`.

Password hashing: PBKDF2-SHA256 now defaults to 600000 iterations (was 100000), set with `pbkdf2Iterations` or `THEAUTH_PBKDF2_ITERATIONS`. The stored format `pbkdf2:<iterations>:<salt>:<hash>` is unchanged, old hashes verify with their own iterations and are upgraded on successful sign-in. Unknown usernames now spend a hash to avoid a timing oracle. Expect about 100 ms per hash; lower the value on CPU-limited Workers plans.
