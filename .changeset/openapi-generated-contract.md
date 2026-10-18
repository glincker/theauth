---
"@glinr/theauth": major
---

`generateOpenAPISpec` now builds the document from the handler's route table and the core result shapes, and the result is checked in as `sdks/openapi.json` with a test that fails on drift.

Upgrade notes:

- `servers[0].url` is `baseUrl` plus the new `basePath` option (default `/api/theauth`). Pass the origin as `baseUrl`.
- Paths now match the served routes. `AuthorizeResult` has a required `code`, and explain, delegation chain fields, approvals and `/mcp/introspect` are described.
- `POST /authorize` and `POST /authorize/token` accept `approvalId`, which was dropped before.
- New options: `handler` (leave out routes the handler does not serve) and `adminApi`.
