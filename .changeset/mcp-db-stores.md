---
"@glinr/theauth": major
"@glinr/create-theauth-app": minor
---

Database backed MCP authorization server, OAuth client to agent binding, and readable denials.

**What is new**

- `createMcpModule({ auth, config, resolveUserId })` keeps clients, authorization codes, access and refresh token records and refresh token families in the TheAuth database, so several instances share state and a restart keeps registered clients. Authorization codes are consumed with a single `DELETE ... RETURNING` (one winner under concurrency). Any store function you also pass wins over the database one, and the old form with seven store functions still works for tests and custom storage. `createMcpStores(db)` returns the database stores as an object.
- Migration `0006` adds `agent_id`, `scope`, `logo_uri`, `jwks`, `jwks_uri`, `user_id` and `source` to `theauth_oauth_clients`, and `jti`, `family_id`, `token_type` and `dpop_jkt` (with indexes on `jti`, `client_id` and `family_id`) to `theauth_oauth_access_tokens`. `agent_id` references `theauth_agents(id)` with `ON DELETE SET NULL` when agents are enabled. Configs with an `mcp` key now also create the oauth tables and the refresh token family tables.
- `mcp.clients.bindAgent(clientId, agentId)`, `unbindAgent` and `agentFor` bind an OAuth client to an agent. Tokens issued to a bound client carry `agent_id` without `agentClaims`. `registration.agentForClient(client, request)` binds at registration (server side only), and `preRegisteredClients[].agentId` binds at startup. `mcp.registerClient(body, request?)` takes the request.
- With `auth`, the live delegation check resolves each actor to the agent its client is bound to, then to its own id, so the hand written `resolveActorAgentId` is only needed for the token subject (a user). Your resolver runs first and falls through to the built-in mapping when it returns `undefined`.
- `requireScopes` returns a typed result: `{ authorized: false, status, error: { code, message }, rejected?, response }`. `error.code` is one of `UNAUTHORIZED`, `INVALID_TOKEN`, `TOKEN_EXPIRED`, `INVALID_AUDIENCE`, `INVALID_ISSUER`, `DELEGATION_REVOKED`, `INSUFFICIENT_SCOPE`, `DPOP_REQUIRED`, `SERVER_ERROR`. `rejected` (`clientId`, `subject`, `agentId?`, `tokenId`) is set only for a token whose signature verified, so a denial can be attributed in an audit log.
- The MCP HTTP responses follow the MCP authorization spec: 401 carries `WWW-Authenticate: Bearer [error="invalid_token", error_description="..."], resource_metadata="...", scope="..."` (no `error` when no token was sent), and the 403 `insufficient_scope` step-up challenge now includes `resource_metadata` and a `code` field in its body. `requireMcpAuth` adds `scope` to its 401 challenges when `requiredScopes` is set.
- The `hono-mcp` template uses the database stores, binds clients through `PUT /admin/mcp-clients/:clientId/agent`, and protects its tools with `mcp.requireScopes`.

**Upgrade notes (breaking)**

- The 401 body from `buildUnauthorizedResponse`, `requireScopes` and `createMcpResponseHelpers(ctx).unauthorizedResponse` is now `{ jsonrpc, error: { code: -32001, message, data: { code } }, id: null }`. The JSON-RPC error code changed from `-32000` to `-32001`, and the `www-authenticate` key inside the body is gone: read the `WWW-Authenticate` header instead.
- `requireScopes` failures gain `status`, `error` and `rejected`. Code that only read `check.response` keeps working; code that matched the type `{ authorized: false; response }` exactly needs the wider `RequireScopesResult`.
- Expired tokens now report `TOKEN_EXPIRED` (before, the validator mapped them to `INVALID_TOKEN` because it matched the wrong jose message). Wrong audience and issuer keep their codes.
- `McpAuthContext` and `McpClient` gained optional members (`setClientAgent`, `agentId`). Custom store implementations need no change.
