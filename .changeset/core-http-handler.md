---
"@glinr/theauth": major
---

Add `@glinr/theauth/http`: one web-standard HTTP handler for every theAuth route, so framework adapters no longer carry their own copy.

New exports: `createTheAuthHandler(auth, options)` returning `(request: Request) => Promise<Response>`, `listRoutes(options)` (the route table, `RouteSpec[]`), `requireAgent(auth, request, { action, resource, clientIp? })`, and the Node bridge `toWebRequest` and `sendWebResponse`. Options extend the existing adapter security options (`authenticate`, `allowUnauthenticated`, `trustedProxy`, `rateLimit`, `trustedOrigins`, `csrf`) with `mcp`, `basePath`, `routes` and `maxBodyBytes` (default 1 MiB, 413 above it).

Behavior changes (breaking):

- `POST /mcp/revoke` (RFC 7009) and `GET /mcp/jwks` are now served. Previously the metadata advertised both and no adapter served them.
- `/.well-known/oauth-authorization-server` and `/.well-known/oauth-protected-resource` list only the MCP endpoints that are mounted (`routes.mcp` accepts `{ register, authorize, token, revoke, jwks }` booleans). New helpers in `@glinr/theauth/mcp`: `applyMountedToServerMetadata`, `applyMountedToResourceMetadata`, `ALL_MCP_ROUTES`.
- New admin route `POST /explain` wrapping `theauth.explain`.
- Status codes are now identical across frameworks: `POST /authorize/token` answers 401 for `invalid_token`, `agent_not_found`, `agent_revoked`, `agent_expired` and 403 for every other denial (it used to answer 403 for both). A known path with the wrong method answers 405 with `Allow`. Unexpected errors answer a fixed 500 message instead of echoing the exception text. `GET /audit` accepts `result=escalated`.
- `requireAgent` branches on the decision code, never on reason strings. Denial bodies are `{ error: { code, message } }` where `code` is the decision code (lowercase, for example `no_permission`), not `UNAUTHORIZED` or `FORBIDDEN`.

Adapter authors: replace each adapter's dispatcher with `createTheAuthHandler` and delete the per-adapter `dispatch.ts`. Option names are the unified ones above.
