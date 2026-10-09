import { and, eq, sql } from "drizzle-orm";
import { generateId } from "../crypto/web-crypto.js";
import type { Database } from "../db/database.js";
import { usernameAccounts, users } from "../db/schema.js";
import type { ImportedUser, MigrationRecord, MigrationStore, StoredUser } from "./types.js";

const LEDGER_DDL = `CREATE TABLE IF NOT EXISTS theauth_migration_ledger (
	id TEXT PRIMARY KEY,
	user_id TEXT,
	source TEXT NOT NULL,
	status TEXT NOT NULL,
	cohort TEXT,
	error_code TEXT,
	at INTEGER NOT NULL
)`;

interface LedgerRow {
	user_id: string | null;
	source: string;
	status: string;
	cohort: string | null;
	error_code: string | null;
	at: number;
}

function toStored(r: typeof users.$inferSelect): StoredUser {
	return { id: r.id, email: r.email, externalId: r.externalId, source: r.externalProvider };
}

/**
 * Store backed by theauth's own tables. Users go into `theauth_users` (external id and
 * source in the existing columns), password hashes into `theauth_username_accounts`
 * keyed by the lowercased email, and progress into `theauth_migration_ledger`, which this
 * creates on first use. The ledger holds ids and counts, never email or hashes.
 */
export async function createDbMigrationStore(db: Database): Promise<MigrationStore> {
	await db.run(sql.raw(LEDGER_DDL));

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
			await db.run(
				sql`INSERT INTO theauth_migration_ledger (id, user_id, source, status, cohort, error_code, at)
					VALUES (${generateId()}, ${r.userId}, ${r.source}, ${r.status}, ${r.cohort}, ${r.errorCode}, ${r.at.getTime()})`,
			);
		},
		async listMigrations() {
			const rows = (await db.all(
				sql`SELECT user_id, source, status, cohort, error_code, at FROM theauth_migration_ledger ORDER BY at ASC`,
			)) as LedgerRow[];
			return rows.map((r) => ({
				userId: r.user_id,
				source: r.source,
				status: r.status as MigrationRecord["status"],
				cohort: r.cohort,
				errorCode: r.error_code,
				at: new Date(r.at),
			}));
		},
	};
}
