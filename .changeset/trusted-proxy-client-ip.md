---
"@glinr/theauth": patch
"@glinr/theauth-hono": patch
"@glinr/theauth-express": patch
---

Resolve the client IP through the trusted proxy helper. The hono and express adapters no longer read `X-Forwarded-For` or `X-Real-IP` directly. By default forwarded headers are ignored (Express still falls back to `req.ip`), so an `ipAllowlist` constraint denies when the IP is unknown. Pass `trustedProxy: { trustedProxyCount }` or `trustedProxy: { trustedHeader }` to the adapter to match your proxy setup.
