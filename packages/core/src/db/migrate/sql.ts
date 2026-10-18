import { BASELINE_ID, MIGRATIONS } from "../migrations/index.js";
import { ledgerCreateSql, ledgerInsertSql } from "./ledger.js";
import type { Dialect, Migration } from "./types.js";

function terminate(statement: string): string {
	return `${statement.trimEnd().replace(/;$/, "")};`;
}

/** SQL for one migration: its statements, then the ledger row, so a hand applied schema reads as applied. */
export function singleMigrationSql(dialect: Dialect, migration: Migration): string {
	const lines = [`/* Migration ${migration.id}: ${migration.name} */`, ""];
	if (migration.id === BASELINE_ID) {
		lines.push(`${terminate(ledgerCreateSql(dialect))}`, "");
	}
	for (const statement of migration.up[dialect]) lines.push(terminate(statement), "");
	lines.push(terminate(ledgerInsertSql(dialect, migration)), "");
	return lines.join("\n");
}

export function findMigrationIndex(id: string): number {
	return MIGRATIONS.findIndex((m) => m.id === id);
}

/**
 * All migration SQL for a dialect, for `database.skipMigrations` users and `theauth db sql`.
 * With `from`, output starts at that migration id and assumes everything before it is already applied: it then also creates the ledger and stamps the baseline, so the database reads as up to date afterwards.
 */
export function migrationSql(dialect: Dialect, options: { from?: string } = {}): string {
	let start = 0;
	if (options.from !== undefined) {
		start = findMigrationIndex(options.from);
		if (start < 0) {
			throw new Error(
				`TheAuth schema: unknown migration id "${options.from}". Known ids: ${MIGRATIONS.map((m) => m.id).join(", ")}.`,
			);
		}
	}
	const parts: string[] = [];
	if (start > 0) {
		parts.push(
			[
				`/* Ledger and baseline stamp: for a database that already has the tables up to migration ${(MIGRATIONS[start - 1] as Migration).id}. */`,
				"",
				terminate(ledgerCreateSql(dialect)),
				"",
				...MIGRATIONS.slice(0, start).flatMap((m) => [terminate(ledgerInsertSql(dialect, m)), ""]),
			].join("\n"),
		);
	}
	for (const m of MIGRATIONS.slice(start)) parts.push(singleMigrationSql(dialect, m));
	return parts.join("\n");
}
