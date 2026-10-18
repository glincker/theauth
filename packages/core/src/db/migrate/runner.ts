import type { TheAuthConfig } from "../../types.js";
import type { Database } from "../database.js";
import { BASELINE_ID, MIGRATIONS } from "../migrations/index.js";
import { createExecutor, isAlreadyExistsError } from "./executor.js";
import type { EnabledFeatures } from "./features.js";
import { resolveEnabledFeatures } from "./features.js";
import type { LedgerRow } from "./ledger.js";
import { ledgerCreateSql, ledgerInsertSql, migrationChecksum, readLedger } from "./ledger.js";
import { isAtBaselineShape, renameLegacyTables } from "./legacy.js";
import { tableExists } from "./probe.js";
import type { Dialect, Migration, MigrationStatus, SchemaProvider, SqlExecutor } from "./types.js";
import { SchemaChecksumError } from "./types.js";

export interface MigrationOptions {
	/** Decides which feature tables exist. Omitted means every feature (backward compatible). */
	config?: TheAuthConfig;
	/** Stop after this migration id. */
	to?: string;
}

/** Migrations that apply to a config, in order, optionally cut off after `to`. */
function applicableMigrations(features: EnabledFeatures, to?: string): Migration[] {
	let list = MIGRATIONS.filter((m) => (m.requires ?? []).every((f) => features[f]));
	if (to !== undefined) {
		const cut = MIGRATIONS.findIndex((m) => m.id === to);
		if (cut < 0) {
			throw new Error(
				`TheAuth schema: unknown migration id "${to}". Known ids: ${MIGRATIONS.map((m) => m.id).join(", ")}.`,
			);
		}
		list = list.filter((m) => MIGRATIONS.indexOf(m) <= cut);
	}
	return list;
}

function findMismatches(rows: LedgerRow[], dialect: Dialect): MigrationStatus["mismatched"] {
	const out: MigrationStatus["mismatched"] = [];
	for (const row of rows) {
		const migration = MIGRATIONS.find((m) => m.id === row.id);
		if (!migration) continue;
		const expected = migrationChecksum(migration, dialect);
		if (expected !== row.checksum) out.push({ id: row.id, expected, actual: row.checksum });
	}
	return out;
}

/** On a database from before the ledger: is this migration's effect already in the schema? */
async function isStampable(
	exec: SqlExecutor,
	migration: Migration,
	features: EnabledFeatures,
): Promise<boolean> {
	if (migration.id === BASELINE_ID) return isAtBaselineShape(exec, features);
	return migration.detect ? migration.detect(exec) : false;
}

/** Reads the ledger and reports what ran and what is pending. Never writes. */
export async function getSchemaStatus(
	db: Database,
	provider: SchemaProvider,
	config?: TheAuthConfig,
): Promise<MigrationStatus> {
	const exec = createExecutor(db, provider);
	const features = resolveEnabledFeatures(config);
	const applicable = applicableMigrations(features);
	const rows = await readLedger(exec);

	if (rows === null) {
		// No ledger. A database that already has TheAuth tables adopts what its schema already contains.
		const adopt = await tableExists(exec, "theauth_users");
		const pending: Migration[] = [];
		for (const m of applicable) {
			if (!(adopt && (await isStampable(exec, m, features)))) pending.push(m);
		}
		return {
			applied: [],
			pending: pending.map((m) => ({ id: m.id, name: m.name })),
			baselineStamped: adopt && !pending.some((m) => m.id === BASELINE_ID),
			mismatched: [],
			unknown: [],
		};
	}

	const recorded = new Set(rows.map((r) => r.id));
	const known = new Set(MIGRATIONS.map((m) => m.id));
	return {
		applied: rows.map((r) => ({ id: r.id, name: r.name, appliedAt: r.appliedAt })),
		pending: applicable.filter((m) => !recorded.has(m.id)).map((m) => ({ id: m.id, name: m.name })),
		baselineStamped: false,
		mismatched: findMismatches(rows, exec.dialect),
		unknown: rows.filter((r) => !known.has(r.id)).map((r) => r.id),
	};
}

/** Runs statements, tolerating only "already exists" so a re-run over a partly upgraded database is safe. */
async function runStatements(exec: SqlExecutor, statements: string[]): Promise<void> {
	for (const sql of statements) {
		try {
			await exec.run(sql);
		} catch (error) {
			if (!isAlreadyExistsError(error)) throw error;
		}
	}
}

function statementsOf(
	migration: Migration,
	exec: SqlExecutor,
	features: EnabledFeatures,
): string[] {
	return migration.statementsFor
		? migration.statementsFor(exec.dialect, features)
		: migration.up[exec.dialect];
}

export interface MigrationRunResult {
	/** Ids recorded in the ledger by this call (or that would be, on a dry run). */
	applied: string[];
	/** The statements executed (or that would be), ledger writes included. */
	sql: string[];
	/** True when the database had tables but no ledger and the baseline was adopted. */
	baselineStamped: boolean;
}

/**
 * Brings the database to the latest schema and records each migration in `theauth_schema_migrations`.
 * Safe to call on every boot: recorded migrations are skipped, and the baseline is re-run (CREATE IF NOT EXISTS) so tables for newly enabled features appear.
 */
export async function runMigrations(
	db: Database,
	provider: SchemaProvider,
	options: MigrationOptions & { dryRun?: boolean } = {},
): Promise<MigrationRunResult> {
	const exec = createExecutor(db, provider);
	const features = resolveEnabledFeatures(options.config);
	const applicable = applicableMigrations(features, options.to);
	const dryRun = options.dryRun === true;
	const sql: string[] = [];
	const applied: string[] = [];

	let rows = await readLedger(exec);
	let adopt = false;
	if (rows === null) {
		sql.push(ledgerCreateSql(exec.dialect));
		if (!dryRun) {
			// Only a database from before the ledger can hold tables under the legacy prefix.
			await renameLegacyTables(exec);
			await exec.run(ledgerCreateSql(exec.dialect));
		}
		adopt = await tableExists(exec, "theauth_users");
		rows = [];
	}

	const mismatched = findMismatches(rows, exec.dialect);
	if (mismatched.length > 0) throw new SchemaChecksumError(mismatched);

	const recorded = new Set(rows.map((r) => r.id));

	for (const migration of applicable) {
		const isBaseline = migration.id === BASELINE_ID;
		const alreadyRecorded = recorded.has(migration.id);
		if (alreadyRecorded && !isBaseline) continue;

		// A pre-ledger database that already contains this migration's effect is stamped, not re-run.
		const stamp = adopt && !isBaseline && (await isStampable(exec, migration, features));
		const insert = ledgerInsertSql(exec.dialect, migration);
		if (!stamp) {
			const statements = statementsOf(migration, exec, features);
			sql.push(...statements);
			if (!dryRun) {
				if (migration.run) await migration.run(exec, { dialect: exec.dialect, features });
				await runStatements(exec, statements);
			}
		}
		if (alreadyRecorded) continue;

		sql.push(insert);
		if (dryRun) {
			applied.push(migration.id);
			continue;
		}
		try {
			await exec.run(insert);
			applied.push(migration.id);
		} catch (error) {
			// Another instance booting at the same time recorded it first: that is fine.
			const now = await readLedger(exec);
			if (!now?.some((r) => r.id === migration.id)) throw error;
		}
	}

	return { applied, sql, baselineStamped: adopt };
}
