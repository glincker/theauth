import type { DatabaseConfig } from "../database.js";
import type { EnabledFeatures, FeatureKey } from "./features.js";

/** SQL dialects TheAuth ships DDL for. */
export type Dialect = "sqlite" | "postgres" | "mysql";

/** Rows come back as plain objects whatever the driver. */
export type SqlRow = Record<string, unknown>;

/** The smallest surface a migration needs: run a statement, read rows. */
export interface SqlExecutor {
	dialect: Dialect;
	run(sql: string): Promise<void>;
	all(sql: string): Promise<SqlRow[]>;
}

/** What a runtime step knows about the boot it runs in. */
export interface MigrationContext {
	dialect: Dialect;
	features: EnabledFeatures;
}

export interface Migration {
	/** Zero padded, sortable: "0004". */
	id: string;
	/** Kebab case: "audit-event". */
	name: string;
	/** The statements that move a database from the previous migration to this one. Also the source of the generated `.sql` files and of the checksum. */
	up: Record<Dialect, string[]>;
	/** The migration only applies when every listed feature is enabled for the config. Skipped migrations stay out of the ledger until the feature is enabled. */
	requires?: FeatureKey[];
	/** Picks the statements to run for this boot (the baseline only creates tables for enabled features). Defaults to `up[dialect]`. */
	statementsFor?: (dialect: Dialect, features: EnabledFeatures) => string[];
	/** For databases that pre-date the ledger: true when this migration's effect is already in the schema, so it is stamped instead of run. Not part of the generated SQL. */
	detect?: (exec: SqlExecutor) => Promise<boolean>;
	/** Runtime only step for upgrades that must inspect the database first (column probes). Runs before the statements. Not part of the generated SQL. */
	run?: (exec: SqlExecutor, ctx: MigrationContext) => Promise<void>;
}

export interface MigrationStatus {
	/** Ledger rows, oldest first. */
	applied: Array<{ id: string; name: string; appliedAt: Date }>;
	/** Migrations that still have to run for this config. */
	pending: Array<{ id: string; name: string }>;
	/** True when the database had TheAuth tables at the baseline shape but no ledger, so the baseline (0000) counts as applied without a ledger row. `theauth db up` writes the row. */
	baselineStamped: boolean;
	/** Ledger rows whose checksum differs from the code (an applied migration was edited). */
	mismatched: Array<{ id: string; expected: string; actual: string }>;
	/** Ledger ids this version does not know (the database was migrated by a newer TheAuth). */
	unknown: string[];
}

export type SchemaProvider = DatabaseConfig["provider"];

/** Thrown when `database.skipMigrations` is set and the schema is behind. */
export class SchemaOutdatedError extends Error {
	readonly pending: string[];
	constructor(pending: string[]) {
		super(
			`TheAuth: the database schema is out of date (pending migrations: ${pending.join(", ")}). ` +
				"You set database.skipMigrations, so apply them first: run `theauth db sql --dialect <sqlite|postgres|mysql>` " +
				"(add `--from <id>` to start at the first pending id) and execute the output, or run `theauth db up`.",
		);
		this.name = "SchemaOutdatedError";
		this.pending = pending;
	}
}

/** Thrown when a migration already recorded in the ledger no longer matches the code. */
export class SchemaChecksumError extends Error {
	readonly mismatched: MigrationStatus["mismatched"];
	constructor(mismatched: MigrationStatus["mismatched"]) {
		super(
			`TheAuth: applied migration(s) ${mismatched.map((m) => m.id).join(", ")} differ from this version of the code ` +
				"(checksum mismatch). A migration was edited after it ran, or the database belongs to a different TheAuth build. " +
				"Do not edit applied migrations: add a new one instead.",
		);
		this.name = "SchemaChecksumError";
		this.mismatched = mismatched;
	}
}
