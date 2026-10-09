import { generateId } from "../crypto/web-crypto.js";
import type { ImportedUser, MigrationRecord, MigrationStore, StoredUser } from "./types.js";

/** In-memory store for tests, dry runs against a scratch copy, and examples. */
export function createMemoryMigrationStore(): MigrationStore & {
	users: Map<string, StoredUser & { imported: ImportedUser }>;
} {
	const users = new Map<string, StoredUser & { imported: ImportedUser }>();
	const hashes = new Map<string, string>();
	const ledger: MigrationRecord[] = [];
	const store: MigrationStore & { users: typeof users } = {
		users,
		async findBySourceId(source, externalId) {
			for (const u of users.values()) {
				if (u.source === source && u.externalId === externalId) return strip(u);
			}
			return null;
		},
		async findByEmail(email) {
			for (const u of users.values()) if (u.email === email.toLowerCase()) return strip(u);
			return null;
		},
		async createUser(user, source) {
			const id = generateId();
			const row = { id, email: user.email, externalId: user.externalId, source, imported: user };
			users.set(id, row);
			return strip(row);
		},
		async updateUser(id, user) {
			const row = users.get(id);
			if (row) users.set(id, { ...row, imported: user });
		},
		async getPasswordHash(userId) {
			return hashes.get(userId) ?? null;
		},
		async setPasswordHash(userId, encoded) {
			hashes.set(userId, encoded);
		},
		async recordMigration(record) {
			ledger.push(record);
		},
		async listMigrations() {
			return [...ledger];
		},
	};
	return store;
}

function strip(u: StoredUser): StoredUser {
	return { id: u.id, email: u.email, externalId: u.externalId, source: u.source };
}
