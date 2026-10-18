import { MIGRATIONS } from "../migrations/index.js";
import { singleMigrationSql } from "./sql.js";
import type { Dialect } from "./types.js";

export const SQL_DIALECTS: readonly Dialect[] = ["sqlite", "postgres", "mysql"];

/**
 * The committed `.sql` files, keyed by path relative to `src/db/migrations`: `sql/<dialect>/<id>.sql`.
 * They are generated output of the TypeScript migrations; a test fails when they drift.
 * Regenerate with `UPDATE_MIGRATION_SQL=1 vitest run packages/core/tests/migrate-sql-snapshot.test.ts`.
 */
export function generatedSqlFiles(): Record<string, string> {
	const files: Record<string, string> = {};
	for (const dialect of SQL_DIALECTS) {
		for (const migration of MIGRATIONS) {
			files[`sql/${dialect}/${migration.id}.sql`] = singleMigrationSql(dialect, migration);
		}
	}
	return files;
}
