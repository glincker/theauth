---
"@glinr/theauth": minor
---

Audit rows now carry a millisecond write-order column, `recorded_at_ms` (migration `0003_add_audit_recorded_at_ms.sql`, applied by `createTables()`, existing rows backfilled), and `audit.query()` orders by it, so rows written in the same second come back in write order. The column is not part of the audit hash, so existing chains and the Go verifier keep verifying. `delegation.revoke()` now writes a chained `delegation.revoke` audit row for each revoked link, cascaded links included. With `skipMigrations: true`, apply the 0003 file by hand. No documented read shape changes.
