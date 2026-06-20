import * as schema from "../src/db/schema.js";
import type { Kavach } from "../src/kavach.js";
import { createKavach } from "../src/kavach.js";

export type { Kavach };

/**
 * Create a test TheAuth instance with in-memory SQLite.
 * Tables are auto-created by createKavach. A seed user is inserted.
 */
export async function createTestKavach(options?: {
	maxPerUser?: number;
	auditAll?: boolean;
}): Promise<Kavach> {
	const kavach = await createKavach({
		database: { provider: "sqlite", url: ":memory:" },
		agents: {
			enabled: true,
			maxPerUser: options?.maxPerUser ?? 10,
			defaultPermissions: [],
			auditAll: options?.auditAll ?? true,
			tokenExpiry: "24h",
		},
	});

	// Seed a test user
	kavach.db
		.insert(schema.users)
		.values({
			id: "user-1",
			email: "test@example.com",
			name: "Test User",
			createdAt: new Date(),
			updatedAt: new Date(),
		})
		.run();

	return kavach;
}
