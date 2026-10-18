---
"@glinr/theauth": major
"@glinr/theauth-cli": minor
---

Versioned schema migrations with a ledger. TheAuth now records every schema change in `theauth_schema_migrations` (`id`, `name`, `checksum`, `applied_at`), runs pending migrations at startup, and exposes the state as `auth.schema.status()`. `createTables()` is a thin call to the new runner. The 1.x tables are migration `0000` (`baseline`); the audit and policy columns are `0001` to `0003`. Ids `0004` to `0006` are reserved for upcoming work.

New `theauth db status | up | sql [--dialect sqlite|postgres|mysql] [--from <id>] [--json]` in the CLI. New exports from `@glinr/theauth`: `getSchemaStatus`, `runSchemaMigrations`, `migrationSql`, `SCHEMA_MIGRATIONS`, `SchemaOutdatedError`, `SchemaChecksumError`.

Upgrade notes:

- **`database.skipMigrations: true` users must apply the ledger SQL.** The schema check now runs at startup: if migrations are pending, `createTheAuth` throws `SchemaOutdatedError` listing their ids instead of failing on the first write. Generate the SQL with `theauth db sql --dialect <yours>` (on a database that already has the 1.x tables use `--from 0002`, which also creates the ledger and stamps `0000` and `0001`), run it with your own tooling, then deploy. Each migration ends with an `INSERT` into the ledger, so it reads as applied. The old hand-run files `0001_*.sql` to `0003_*.sql` are replaced by generated files under `src/db/migrations/sql/<dialect>/`.
- Databases without the ledger are adopted, not rebuilt: tables found at the 1.x shape are stamped as applied and only the missing migrations run. Existing rows are untouched.
- An applied migration whose SQL no longer matches its ledger checksum stops startup with `SchemaChecksumError`.
- `decision_code` and `recorded_at_ms` stay out of the audit hash, so existing chains keep verifying.
- `src/db/schema.ts` is now a barrel over `src/db/schema/*.ts` and the DDL moved to `src/db/ddl/*.ts`. Public imports are unchanged.
- Postgres and MySQL now have a dialect test suite (`packages/core/tests/dialect`, opt in with `THEAUTH_TEST_PG_URL` and `THEAUTH_TEST_MYSQL_URL`). See the Database setup and storage pages for what it covers.
