import type { TheAuthConfig } from "../types.js";
import type { Database, DatabaseProvider } from "./database.js";
import { databaseProvider } from "./database.js";
import type { MigrationStatus } from "./migrate/index.js";
import {
	assertAuditSecretsLayout,
	createExecutor,
	getSchemaStatus,
	runMigrations,
	SchemaOutdatedError,
} from "./migrate/index.js";

/**
 * Create or upgrade TheAuth tables. Safe to call on every startup: applied migrations are skipped (see `theauth_schema_migrations`) and table creation uses `CREATE TABLE IF NOT EXISTS`. When `config` is provided, only tables required by the configured features are created. When omitted, all tables are created (backward-compatible behaviour for callers that do not pass a config).
 *
 * @example
 * ```typescript
 * const db = await createDatabase({ provider: 'postgres', url: process.env.DATABASE_URL });
 * await createTables(db, 'postgres');
 * ```
 */
export async function createTables(
	db: Database,
	provider: DatabaseProvider,
	config?: TheAuthConfig,
): Promise<void> {
	await runMigrations(db, provider, { config });
}

/**
 * Boot path used by `createTheAuth`: migrate, or with `database.skipMigrations` verify and fail loudly if the schema is behind.
 */
export async function ensureSchema(db: Database, config: TheAuthConfig): Promise<void> {
	const provider = databaseProvider(config.database);
	if (!config.database.skipMigrations) {
		await createTables(db, provider, config);
		return;
	}
	// D1 has no raw executor, so its schema cannot be inspected from here.
	if (provider === "d1") return;
	await assertAuditSecretsLayout(createExecutor(db, provider));
	const status = await getSchemaStatus(db, provider, config);
	if (status.pending.length > 0) throw new SchemaOutdatedError(status.pending.map((m) => m.id));
}

/** The `auth.schema` surface on the core instance. */
export interface SchemaApi {
	/** Applied and pending migrations, read from `theauth_schema_migrations`. */
	status(): Promise<MigrationStatus>;
}

export function createSchemaApi(db: Database, config: TheAuthConfig): SchemaApi {
	return { status: () => getSchemaStatus(db, databaseProvider(config.database), config) };
}
