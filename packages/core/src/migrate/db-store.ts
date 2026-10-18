import { and, asc, eq, sql } from "drizzle-orm";
import { integer, sqliteTable, text } from "drizzle-orm/sqlite-core";
import { generateId } from "../crypto/web-crypto.js";
import type { Database } from "../db/database.js";
import { createExecutor, toDialect } from "../db/migrate/executor.js";
import type { Dialect, SchemaProvider } from "../db/migrate/types.js";
import { usernameAccounts, users } from "../db/schema.js";
import type { ImportedUser, MigrationRecord, MigrationStore, StoredUser } from "./types.js";

/** Ledger DDL per dialect. `at` is epoch milliseconds, which needs 64 bits on Postgres and MySQL. */
function ledgerDdl(dialect: Dialect): string {
	const idType = dialect === "mysql" ? "VARCHAR(191)" : "TEXT";
	const textType = dialect === "mysql" ? "VARCHAR(191)" : "TEXT";
	const atType = dialect === "sqlite" ? "INTEGER" : "BIGINT";
	return `CREATE TABLE IF NOT EXISTS theauth_migration_ledger (
	id ${idType} PRIMARY KEY,
	user_id ${textType},
	source ${textType} NOT NULL,
	status ${textType} NOT NULL,
	cohort ${textType},
	error_code ${textType},
	at ${atType} NOT NULL
)${dialect === "mysql" ? " ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin" : ""}`;
}

const ledger = sqliteTable("theauth_migration_ledger", {
	id: text("id").primaryKey(),
	userId: text("user_id"),
	source: text("source").notNull(),
	status: text("status").notNull(),
	cohort: text("cohort"),
	errorCode: text("error_code"),
	// BIGINT on Postgres comes back as a string; read through mapWith(Number).
	at: integer("at").notNull(),
});

/** Picks the SQL dialect from the Drizzle instance when the caller does not say. */
function detectProvider(db: Database): SchemaProvider {
	const dialectName = (db as unknown as { dialect?: { constructor?: { name?: string } } }).dialect
		?.constructor?.name;
	if (dialectName === "PgDialect") return "postgres";
	if (dialectName === "MySqlDialect") return "mysql";
	return "sqlite";
}

function toStored(r: typeof users.$inferSelect): StoredUser {
	return { id: r.id, email: r.email, externalId: r.externalId, source: r.externalProvider };
}

/**
 * Store backed by theauth's own tables. Users go into `theauth_users` (external id and source in the existing columns), password hashes into `theauth_username_accounts` keyed by the lowercased email, and progress into `theauth_migration_ledger`, which this creates on first use. The ledger holds ids and counts, never email or hashes.
 */
export async function createDbMigrationStore(
	db: Database,
	provider: SchemaProvider = detectProvider(db),
): Promise<MigrationStore> {
	await createExecutor(db, provider).run(ledgerDdl(toDialect(provider)));

	async function userById(id: string): Promise<typeof users.$inferSelect | undefined> {
		return (await db.select().from(users).where(eq(users.id, id)))[0];
	}

	return {
		async findBySourceId(source, externalId) {
			const rows = await db
				.select()
				.from(users)
				.where(and(eq(users.externalProvider, source), eq(users.externalId, externalId)));
			return rows[0] ? toStored(rows[0]) : null;
		},
		async findByEmail(email) {
			const rows = await db.select().from(users).where(eq(users.email, email.toLowerCase()));
			return rows[0] ? toStored(rows[0]) : null;
		},
		async createUser(user: ImportedUser, source: string) {
			const now = new Date();
			const id = generateId();
			await db.insert(users).values({
				id,
				email: user.email,
				name: user.name,
				externalId: user.externalId,
				externalProvider: source,
				emailVerified: user.emailVerified ? 1 : 0,
				metadata: { ...user.metadata, linkedAccounts: user.linkedAccounts },
				createdAt: now,
				updatedAt: now,
			});
			return { id, email: user.email, externalId: user.externalId, source };
		},
		async updateUser(id, user) {
			await db
				.update(users)
				.set({
					name: user.name,
					externalId: user.externalId,
					emailVerified: user.emailVerified ? 1 : 0,
					metadata: { ...user.metadata, linkedAccounts: user.linkedAccounts },
					updatedAt: new Date(),
				})
				.where(eq(users.id, id));
		},
		async getPasswordHash(userId) {
			const rows = await db
				.select()
				.from(usernameAccounts)
				.where(eq(usernameAccounts.userId, userId));
			return rows[0]?.passwordHash ?? null;
		},
		async setPasswordHash(userId, encoded) {
			const user = await userById(userId);
			if (!user) throw new Error("user not found");
			const now = new Date();
			const existing = await db
				.select()
				.from(usernameAccounts)
				.where(eq(usernameAccounts.userId, userId));
			if (existing[0]) {
				await db
					.update(usernameAccounts)
					.set({ passwordHash: encoded, updatedAt: now })
					.where(eq(usernameAccounts.userId, userId));
			} else {
				await db.insert(usernameAccounts).values({
					id: generateId(),
					userId,
					username: user.email.toLowerCase(),
					passwordHash: encoded,
					createdAt: now,
					updatedAt: now,
				});
			}
		},
		async recordMigration(r: MigrationRecord) {
			await db.insert(ledger).values({
				id: generateId(),
				userId: r.userId,
				source: r.source,
				status: r.status,
				cohort: r.cohort,
				errorCode: r.errorCode,
				at: r.at.getTime(),
			});
		},
		async listMigrations() {
			const rows = await db
				.select({
					userId: ledger.userId,
					source: ledger.source,
					status: ledger.status,
					cohort: ledger.cohort,
					errorCode: ledger.errorCode,
					at: sql<number>`${ledger.at}`.mapWith(Number),
				})
				.from(ledger)
				.orderBy(asc(ledger.at));
			return rows.map((r) => ({
				userId: r.userId,
				source: r.source,
				status: r.status as MigrationRecord["status"],
				cohort: r.cohort,
				errorCode: r.errorCode,
				at: new Date(r.at),
			}));
		},
	};
}
