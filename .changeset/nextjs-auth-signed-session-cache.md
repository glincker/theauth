---
"@glinr/theauth-nextjs-auth": major
---

Security fix: `@glinr/theauth-nextjs-auth` 0.2.0 and earlier have a session forgery vulnerability. The session cache cookie was unsigned JSON and `getServerSession` returned it without checking a session token with the backend, so any user could hand-write the cookie and be treated as any user or role. Every user of 0.2.0 or earlier must upgrade.

Breaking changes:

- `createAuthConfig` now requires `secret`, at least 32 bytes (for example `openssl rand -base64 48` in a server-only env var). It throws at construction when the secret is missing or too short.
- The session cache cookie is now HMAC-SHA256 signed (keys derived with HKDF), bound to a hash of the session token and to an expiry no later than the session expiry, and verified in constant time. Any mismatch falls back to the backend. Old unsigned cookies are ignored (one extra backend call, no error). `getServerSession` also returns null without a session token regardless of other cookies.
- Cookies are `Secure` by default and no longer depend on `NODE_ENV`. Pass `secure: false` for localhost development over http only; cookies are forced Secure on https requests. `isProd` now only controls the `__Host-` name prefix. The cache cookie uses the `__Host-` prefix when the prefix is in use.
- Cookie expiry on sign-out and refresh failure now sets `Secure` so browsers accept clearing `__Host-` cookies.

- The middleware gate now requires a signed marker cookie (HMAC of the token under an HKDF derived key, Web Crypto only, no backend call), so an arbitrary token cookie no longer passes. It is still not authorization: use `getServerSession`. Sessions without the marker must refresh once.
- CSRF is now a real signed double submit: HMAC tokens bound to the session token, verified in constant time (`verifyCsrfRequest`), enforced by `createSignOutHandler(csrfToken)` and the new `createSignOutRouteHandler`. `setSessionCookies` is async, no longer takes `csrfToken` and returns the signed token; `generateCsrfToken` is deprecated.
- Plain cookie names are ignored once the `__Host-` names are in use (cookie shadowing, subdomain injection). Migrate with `legacyCookieNames: true` (default false), which accepts plain only when the `__Host-` cookie is absent.

Also added: `safeRedirectPath` for `?next=` handling, and `withAuth` rejects a `signInPath` that is not a same-origin path. Workaround on old versions: set `cookieCacheMaxAgeMs: 0`.
