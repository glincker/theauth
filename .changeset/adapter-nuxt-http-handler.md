---
"@glinr/theauth-nuxt": major
---

Rebuild the Nuxt adapter as a thin wrapper around `createTheAuthHandler` from `@glinr/theauth/http`. The 833 line per-adapter dispatcher and router are gone, so the adapter serves every route core serves, including `POST /mcp/revoke`, `GET /mcp/jwks` and `POST /explain`.

Added: `requireScope(theauth, { action, resource, clientIp? }, handler)`, a Nuxt event handler wrapper that sets `event.context.agent`. It answers 401 (`invalid_token`, `agent_not_found`, `agent_revoked`, `agent_expired`) or 403 (any other denial) with body `{ error: { code, message } }` and passes the agent on.

Upgrade notes:

- Removed the deprecated aliases `authNuxt` and `AuthNuxtOptions`. Use `theAuthNuxt` and `TheAuthNuxtOptions`.
- `TheAuthNuxtOptions` is now the core handler options: `mcp`, `basePath`, `routes`, `maxBodyBytes` plus the shared security options (`authenticate`, `allowUnauthenticated`, `trustedProxy`, `rateLimit`, `trustedOrigins`, `csrf`). Existing option names keep working.
- `POST /authorize/token` now answers 401 (not 403) for a revoked, expired or unknown agent or a bad token, and 403 for every other denial. A known path with the wrong method answers 405. Unexpected errors answer a fixed 500 message.
- Request bodies above 1 MiB answer 413 (`maxBodyBytes`).
- The Nuxt handler now streams the raw request body through h3 `toWebRequest` instead of re-serialising it as JSON, so form encoded bodies such as `POST /mcp/token` work.
