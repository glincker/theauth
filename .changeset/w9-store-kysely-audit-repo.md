---
"@glinr/theauth": patch
---

Audit writes now go through a repository (`readHead`, `appendAt`, `insertUnchained`) on the store layer, and the per agent write queue lives on the stores object instead of a map keyed by the Drizzle handle. Behavior is unchanged on the Drizzle path. A Kysely kernel (Postgres, MySQL, SQLite, SQL Server) and generated SQL Server DDL for the core tables exist as internal code, tested against the store contract on all four engines. They are not exposed as a `database` option yet, because most of core still queries through Drizzle (see Choose a storage backend). `kysely` is an optional peer dependency for that code.

Fixes:

- MySQL: `deviceEnrollments.spendUse` read the row back with its own filters after incrementing, so the last allowed use of an enrollment (and any use that made `uses` reach `maxUses`) read as refused while the use was still consumed. A one use enrollment could not be redeemed. The increment now reads its own value through `LAST_INSERT_ID(expr)` on one connection, which also stops a concurrent caller's value leaking into the result.
- Audit rows: a NUL character (U+0000) in a text or JSON field made Postgres refuse the insert, and made sql.js cut the string so the stored row no longer matched its hash and the chain failed verification for good. NUL is now replaced with U+FFFD before the row is hashed, on every backend.
