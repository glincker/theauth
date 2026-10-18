---
"@glinr/theauth-tanstack": major
---

Rebuild the TanStack adapter as a thin wrapper around `createTheAuthHandler` from `@glinr/theauth/http`. The 833 line per-adapter dispatcher and router are gone, so the adapter serves every route core serves, including `POST /mcp/revoke`, `GET /mcp/jwks` and `POST /explain`.

Added: `requireScope(theauth, { action, resource, clientIp? }, handler)`, a TanStack Start route wrapper that passes the agent as the second argument and sets `context.agent` when present. It answers 401 (`invalid_token`, `agent_not_found`, `agent_revoked`, `agent_expired`) or 403 (any other denial) with body `{ error: { code, message } }` and passes the agent on.

Upgrade notes:

- Removed the deprecated aliases `authTanStack`, `AuthTanStackOptions` and `AuthTanStackHandlers`. Use `theAuthTanStack` and `TheAuthTanStackOptions`.
- `TheAuthTanStackOptions` is now the core handler options: `mcp`, `basePath`, `routes`, `maxBodyBytes` plus the shared security options (`authenticate`, `allowUnauthenticated`, `trustedProxy`, `rateLimit`, `trustedOrigins`, `csrf`). Existing option names keep working.
- `POST /authorize/token` now answers 401 (not 403) for a revoked, expired or unknown agent or a bad token, and 403 for every other denial. A known path with the wrong method answers 405. Unexpected errors answer a fixed 500 message.
- Request bodies above 1 MiB answer 413 (`maxBodyBytes`).
- Route handlers now accept either the server route context (an object with `request`) or a bare `Request`.
