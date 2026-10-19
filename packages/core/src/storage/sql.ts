import type { IncrResult, SecondaryStorage } from "./types.js";

export type SqlStorageDialect = "sqlite" | "postgres" | "mysql" | "mssql";

/** What one statement returns. `affectedRows` is the number of rows an INSERT, UPDATE or DELETE touched. */
export interface SqlRunResult {
	rows: Array<Record<string, unknown>>;
	affectedRows: number;
}

/** Runs one statement. Parameters are positional: write `?` in the text and the storage rewrites it to the dialect's own placeholder style before calling you. */
export type SqlRun = (text: string, params: unknown[]) => Promise<SqlRunResult>;

export interface SqlStorageOptions {
	dialect: SqlStorageDialect;
	run: SqlRun;
	/** Table name. Letters, digits and underscores only. Default `theauth_secondary_storage`. */
	table?: string;
}

export interface SqlStorage extends SecondaryStorage {
	/** Create the table when it does not exist. Safe to call on every start. */
	ensureTable(): Promise<void>;
	/** Delete every expired row. Run it from a cron if you write many distinct keys. */
	purgeExpired(): Promise<void>;
}

const MAX_INCR_ATTEMPTS = 4;
const SAFE_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;

function placeholders(dialect: SqlStorageDialect, text: string): string {
	if (dialect === "sqlite" || dialect === "mysql") return text;
	let n = 0;
	return text.replace(/\?/g, () => {
		n += 1;
		return dialect === "postgres" ? `$${n}` : `@p${n}`;
	});
}

/** Escape LIKE wildcards with "!" (declared with ESCAPE '!', which every dialect here accepts). */
function escapeLike(prefix: string): string {
	return prefix.replace(/[!%_[]/g, "!$&");
}

function ddl(dialect: SqlStorageDialect, table: string): string {
	switch (dialect) {
		case "mssql":
			return `IF OBJECT_ID(N'${table}', N'U') IS NULL CREATE TABLE ${table} (storage_key NVARCHAR(450) NOT NULL PRIMARY KEY, storage_value NVARCHAR(MAX) NULL, counter BIGINT NULL, expires_at BIGINT NULL)`;
		case "mysql":
			return `CREATE TABLE IF NOT EXISTS ${table} (storage_key VARCHAR(191) NOT NULL PRIMARY KEY, storage_value LONGTEXT NULL, counter BIGINT NULL, expires_at BIGINT NULL)`;
		case "postgres":
			return `CREATE TABLE IF NOT EXISTS ${table} (storage_key TEXT PRIMARY KEY, storage_value TEXT, counter BIGINT, expires_at BIGINT)`;
		default:
			return `CREATE TABLE IF NOT EXISTS ${table} (storage_key TEXT PRIMARY KEY, storage_value TEXT, counter INTEGER, expires_at INTEGER)`;
	}
}

/**
 * Secondary storage over plain SQL, for databases the main schema does not cover (Microsoft SQL Server) or when you already hold a Kysely, Knex or raw driver handle. You supply one function that runs a parameterised statement.
 * Only INSERT, UPDATE, DELETE and primary key SELECT are used, so it behaves the same on SQLite, Postgres, MySQL and SQL Server.
 * `incr` is atomic per key: the counter moves in a single guarded UPDATE. Two callers racing to open the same window collide on the primary key, and the loser retries as an UPDATE.
 */
export function sqlStorage(options: SqlStorageOptions): SqlStorage {
	const table = options.table ?? "theauth_secondary_storage";
	if (!SAFE_NAME.test(table)) {
		throw new Error(`sqlStorage: table name "${table}" must be letters, digits and underscores`);
	}
	const { dialect } = options;
	const run = (text: string, params: unknown[]) => options.run(placeholders(dialect, text), params);

	async function readLive(key: string, now: number) {
		const { rows } = await run(
			`SELECT storage_value, counter, expires_at FROM ${table} WHERE storage_key = ?`,
			[key],
		);
		const row = rows[0];
		if (!row) return null;
		const expiresAt =
			row.expires_at === null || row.expires_at === undefined ? null : Number(row.expires_at);
		if (expiresAt !== null && expiresAt <= now) return null;
		return {
			value: (row.storage_value ?? null) as string | null,
			counter: row.counter === null || row.counter === undefined ? null : Number(row.counter),
			expiresAt,
		};
	}

	return {
		atomicIncr: true,
		async ensureTable() {
			await run(ddl(dialect, table), []);
		},
		async get(key) {
			const row = await readLive(key, Date.now());
			if (!row) return null;
			return row.counter !== null ? String(row.counter) : row.value;
		},
		async set(key, value, ttlSeconds) {
			const expiresAt = ttlSeconds === undefined ? null : Date.now() + ttlSeconds * 1000;
			const updated = await run(
				`UPDATE ${table} SET storage_value = ?, counter = NULL, expires_at = ? WHERE storage_key = ?`,
				[value, expiresAt, key],
			);
			if (updated.affectedRows > 0) return;
			try {
				await run(
					`INSERT INTO ${table} (storage_key, storage_value, counter, expires_at) VALUES (?, ?, NULL, ?)`,
					[key, value, expiresAt],
				);
			} catch {
				// Lost a race with another writer: last write wins.
				await run(
					`UPDATE ${table} SET storage_value = ?, counter = NULL, expires_at = ? WHERE storage_key = ?`,
					[value, expiresAt, key],
				);
			}
		},
		async delete(key) {
			await run(`DELETE FROM ${table} WHERE storage_key = ?`, [key]);
		},
		async incr(key, ttlSeconds): Promise<IncrResult> {
			for (let attempt = 0; attempt < MAX_INCR_ATTEMPTS; attempt++) {
				const now = Date.now();
				const bumped = await run(
					`UPDATE ${table} SET counter = counter + 1 WHERE storage_key = ? AND counter IS NOT NULL AND expires_at > ?`,
					[key, now],
				);
				if (bumped.affectedRows > 0) {
					const row = await readLive(key, now);
					if (row && row.counter !== null && row.expiresAt !== null) {
						return { count: row.counter, expiresAt: row.expiresAt };
					}
					continue;
				}
				const expiresAt = now + ttlSeconds * 1000;
				const restarted = await run(
					`UPDATE ${table} SET counter = 1, storage_value = NULL, expires_at = ? WHERE storage_key = ? AND (counter IS NULL OR expires_at IS NULL OR expires_at <= ?)`,
					[expiresAt, key, now],
				);
				if (restarted.affectedRows > 0) return { count: 1, expiresAt };
				try {
					await run(
						`INSERT INTO ${table} (storage_key, storage_value, counter, expires_at) VALUES (?, NULL, 1, ?)`,
						[key, expiresAt],
					);
					return { count: 1, expiresAt };
				} catch (error) {
					if (attempt === MAX_INCR_ATTEMPTS - 1) throw error;
				}
			}
			throw new Error("sqlStorage: incr did not settle after retries");
		},
		async list(prefix) {
			const { rows } = await run(
				`SELECT storage_key FROM ${table} WHERE storage_key LIKE ? ESCAPE '!' AND (expires_at IS NULL OR expires_at > ?)`,
				[`${escapeLike(prefix)}%`, Date.now()],
			);
			return rows.map((row) => String(row.storage_key));
		},
		async purgeExpired() {
			await run(`DELETE FROM ${table} WHERE expires_at IS NOT NULL AND expires_at <= ?`, [
				Date.now(),
			]);
		},
	};
}

/** The part of Kysely's `CompiledQuery` class this helper calls. Pass the real class: `CompiledQuery` from `kysely`. */
export interface KyselyCompiledQueryClass {
	raw(sql: string, parameters?: unknown[]): unknown;
}

/** The part of a Kysely instance this helper calls. */
export interface KyselyLike {
	executeQuery(compiledQuery: never): Promise<{
		rows: Array<Record<string, unknown>>;
		numAffectedRows?: bigint | number | undefined;
		numChangedRows?: bigint | number | undefined;
	}>;
}

export interface KyselyStorageOptions {
	dialect: SqlStorageDialect;
	/** The `CompiledQuery` class exported by kysely. */
	CompiledQuery: KyselyCompiledQueryClass;
	table?: string;
}

/**
 * `sqlStorage` wired to a Kysely instance, so any Kysely dialect works: SQLite and D1, Postgres, MySQL, SQL Server. Kysely is not a dependency of TheAuth; you pass its `CompiledQuery` class in.
 */
export function kyselyStorage(db: KyselyLike, options: KyselyStorageOptions): SqlStorage {
	return sqlStorage({
		dialect: options.dialect,
		...(options.table !== undefined ? { table: options.table } : {}),
		run: async (text, params) => {
			const result = await db.executeQuery(options.CompiledQuery.raw(text, params) as never);
			// Kysely reports touched rows as a bigint, or undefined for a SELECT or a driver that does not count.
			const affected = result.numAffectedRows ?? result.numChangedRows ?? 0;
			return { rows: result.rows, affectedRows: Number(affected) };
		},
	});
}
