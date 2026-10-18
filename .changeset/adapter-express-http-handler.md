---
"@glinr/theauth-express": major
---

Rebuilt on the core HTTP handler (`createTheAuthHandler` from `@glinr/theauth/http`) using `toWebRequest` and `sendWebResponse`. `theAuthExpress` is now thin glue and serves every route, including `POST /mcp/revoke`, `GET /mcp/jwks` and `POST /explain`.

Upgrade notes:

- `TheAuthExpressOptions` is now the core `TheAuthHandlerOptions` (`mcp`, `basePath`, `routes`, `maxBodyBytes` and the existing security options). `basePath` defaults to where you mount the router. Bodies over `maxBodyBytes` (1 MiB) get 413.
- Removed the deprecated `authExpress` alias. Use `theAuthExpress`.
- `POST /authorize/token` answers 401 for `invalid_token`, `agent_not_found`, `agent_revoked` and `agent_expired`, and 403 for every other denial. A known path with the wrong method answers 405.
- `requireScope` now uses the core `requireAgent` decision-code mapping. Denial bodies are `{ error: { code, message } }` with the decision code (for example `no_permission`) instead of `UNAUTHORIZED` or `FORBIDDEN`. `getAgent(res)` no longer returns the token.
- The client IP no longer falls back to `req.ip`. Set `trustedProxy` to resolve it from forwarded headers.
