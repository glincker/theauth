---
"@glinr/theauth": minor
---

Add a nullable `decision_code` column to `theauth_audit_logs` (not part of the audit hash, so existing chains and the Go verifier stay valid). Every authorization row now records its decision code, `AuditEntry.code` exposes it, and `audit.query({ codes })` filters on it. A `beforeAuthorize` block, timeout or error now writes a chained audit row (code `hook_denied`, `hook_timeout`, `hook_error` or `approval_required`, with `theauthHook` details in `parameters`) and returns its id as `auditId`. `createTables()` migrates existing databases on startup; with `skipMigrations: true` apply `src/db/migrations/0002_add_audit_decision_code.sql` by hand before upgrading.
