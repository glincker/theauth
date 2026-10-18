---
"@glinr/theauth-nextjs": major
---

Rebuilt on the core HTTP handler (`createTheAuthHandler` from `@glinr/theauth/http`). `theAuthNextjs` returns the handler for each method and serves every route, including `POST /mcp/revoke`, `GET /mcp/jwks` and `POST /explain`.

Upgrade notes:

- `TheAuthNextjsOptions` is now the core `TheAuthHandlerOptions` (`mcp`, `basePath` default `/api/theauth`, `routes`, `maxBodyBytes` and the existing security options).
- Removed the deprecated `authNextjs`, `AuthNextjsOptions` and `AuthNextjsHandlers`. Use `theAuthNextjs`, `TheAuthNextjsOptions` and `TheAuthNextjsHandlers`.
- `POST /authorize/token` answers 401 for `invalid_token`, `agent_not_found`, `agent_revoked` and `agent_expired`, and 403 for every other denial. `GET /audit/export` ignores a `userId` query value and returns only the caller rows (it used to answer 403 for another user).
- `requireScope` now uses the core `requireAgent` decision-code mapping. Denial bodies are `{ error: { code, message } }` with the decision code (for example `no_permission`) instead of `UNAUTHORIZED` or `FORBIDDEN`. The handler receives the agent without its token.
