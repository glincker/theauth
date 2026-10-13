---
"@glinr/theauth-extension": minor
---

Add `@glinr/theauth-extension`: OAuth 2.1 authorization code with PKCE (S256), state and nonce for Manifest V3 browser extensions through `identity.launchWebAuthFlow`. Includes RFC 8414 discovery, RFC 8707 resource indicators, single flight token refresh that survives service worker restarts, optional AES-GCM sealing of the refresh token with a non-extractable key, optional DPoP through `@glinr/theauth-client`, and `exposeAuthToBackground` / `createAuthClient` so popups and content scripts get access tokens without ever receiving the refresh token.
