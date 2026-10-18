---
"@glinr/theauth-hono": major
---

Rebuilt on the core HTTP handler (`createTheAuthHandler` from `@glinr/theauth/http`). `theAuthHono` is now about 40 lines of glue and serves every route, including `POST /mcp/revoke`, `GET /mcp/jwks` and `POST /explain`.

Upgrade notes:

- `TheAuthHonoOptions` is now the core `TheAuthHandlerOptions` (`mcp`, `basePath`, `routes`, `maxBodyBytes` and the existing security options). `basePath` defaults to the path you mount the app under.
- Removed the deprecated `authHono` alias. Use `theAuthHono` (or `createHonoAdapter`).
- `POST /authorize/token` answers 401 for `invalid_token`, `agent_not_found`, `agent_revoked` and `agent_expired`, and 403 for every other denial. A known path with the wrong method answers 405.
- `requireScope` now uses the core `requireAgent` decision-code mapping. Denial bodies are `{ error: { code, message } }` with the decision code (for example `no_permission`) instead of `UNAUTHORIZED` or `FORBIDDEN`. `c.get("agent")` no longer carries the token.
