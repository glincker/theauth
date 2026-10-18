---
"@glinr/theauth": major
---

The core HTTP handler now sets `Cache-Control: no-store` and `Pragma: no-cache` on every response by default (a route's own value wins; `GET /mcp/jwks` stays public), and adds opt-in `securityHeaders` and `cors` options.

Visible behavior changes, hence major:

- The MCP routes no longer send `Access-Control-Allow-Origin: *`, and the handler no longer answers every `OPTIONS` on `/mcp/*` and `/.well-known/*` with wildcard CORS. Browser MCP clients need `cors: { origins: [...] }` (or `origins: ["*"]` for the public discovery documents only). `token`, `introspect` and `revoke` are never CORS enabled unless named under `cors.groups`.
- `OPTIONS` on a served path answers 204 with `Allow`, before authentication.
- Discovery documents and other responses that had no `Cache-Control` now carry `no-store`.
- `MCP_CORS_HEADERS` and `mcpPreflight` were internal and are removed.

New: `securityHeaders` option (nosniff, no-referrer, CORP, HSTS only over https or a trusted proxy, frame and CSP on HTML), the `securityHeaders()` and `isSecureRequest()` helpers from `@glinr/theauth/http`, and a startup warning through the observability logger for `allowUnauthenticated` and permissive CORS.
