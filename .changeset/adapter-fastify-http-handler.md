---
"@glinr/theauth-fastify": major
---

Rebuilt on the core HTTP handler (`createTheAuthHandler` from `@glinr/theauth/http`) using `toWebRequest` and `sendWebResponse`. `theAuthFastify` is now thin glue and serves every route, including `POST /mcp/revoke`, `GET /mcp/jwks` and `POST /explain`. New `requireScope(auth, { action, resource })` preHandler and `getAgent(request)`.

Upgrade notes:

- `TheAuthFastifyOptions` is now the core `TheAuthHandlerOptions` (`mcp`, `basePath`, `routes`, `maxBodyBytes` and the existing security options). `basePath` defaults to the prefix the plugin is registered under.
- Inside the plugin the request body is no longer parsed by Fastify (the handler reads it itself). Your own routes outside the plugin are unaffected.
- Removed the deprecated `authFastify` and `AuthFastifyOptions`. Use `theAuthFastify` and `TheAuthFastifyOptions`.
- `POST /authorize/token` answers 401 for `invalid_token`, `agent_not_found`, `agent_revoked` and `agent_expired`, and 403 for every other denial.
- The client IP now comes from the socket peer address, or from forwarded headers when `trustedProxy` is set.
