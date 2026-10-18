---
"@glinr/theauth": major
"@glinr/theauth-fastify": patch
---

Core: `toWebRequest` now records the socket remote address out of band, exposed as `peerAddressOf(request)`. Without `trustedProxy` the handler, rate limiter and `requireAgent` use that peer address as the client IP, so per-IP limits and `ipAllowlist` work on direct Express, Fastify and NestJS deployments. Forwarded headers are still only believed when `trustedProxy` is set. `requireAgent` accepts `trustedProxy`.

Breaking: `GET /audit/export?userId=<other user>` by a caller limited to their own resources is now `403` with `{ error: { code, message } }` instead of silently returning the caller's rows.

Fastify: the handler is built once at registration, so `allowUnauthenticated` warns once. `requireScope` matches `ipAllowlist` against the socket peer by default. The fail-closed check without an authenticator now surfaces when the plugin registers instead of at `theAuthFastify(...)`.
