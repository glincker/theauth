---
"@glinr/theauth": minor
"@glinr/theauth-gateway": minor
"@glinr/theauth-mcp": minor
"@glinr/theauth-cli": minor
"@glinr/theauth-dashboard": minor
---

Input provenance end to end.

- Content hashes in `input_provenance` are now HMAC-SHA-256 under an HKDF subkey of the audit key (version tag `hv: 2`). Old plain hashes still match. `hashInputContent(content, auditKey)` takes the key now, `hashInputContentPlain` is the old function (breaking for callers that hashed themselves, see `docs/upgrading-to-2.mdx`).
- `audit.query({ provenance: { content } })` hashes on the server and matches keyed and plain rows. `AuditEntry.inputs` exposes the recorded sources.
- `POST /authorize` and `POST /authorize/token` accept `inputs` or a `TheAuth-Inputs` header. `GET /audit` takes `provenanceKind`, `provenanceHash` and `provenanceContent`. `sdks/openapi.json` is regenerated.
- Gateway reads `TheAuth-Inputs`, records it on permission checks and audit entries, and strips it before the upstream. The admin MCP server reads `_meta["io.theauth/inputs"]` and `query_audit` takes provenance filters.
- `theauth audit query` with `--provenance <kind>[:<hash>]` and `--input-content`, and an Inputs column with chips on the dashboard audit page.
- `policy.taint.inputLabels` (off by default) turns the kinds of `context.inputs` into `input:<kind>` call labels, so a taint rule can hold a tool such as `tool:exec` for approval after a retrieved document was in context.
