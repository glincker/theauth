import * as schema from "../src/db/schema.js";
import type { TheAuth } from "../src/theauth.js";
import { createTheAuth } from "../src/theauth.js";

export type { TheAuth };

/**
 * Create a test TheAuth instance with in-memory SQLite.
 * Tables are auto-created by createTheAuth. A seed user is inserted.
 */
export async function createTestTheAuth(options?: {
	maxPerUser?: number;
	auditAll?: boolean;
}): Promise<TheAuth> {
	const theauth = await createTheAuth({
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
	theauth.db
		.insert(schema.users)
		.values({
			id: "user-1",
			email: "test@example.com",
			name: "Test User",
			createdAt: new Date(),
			updatedAt: new Date(),
		})
		.run();

	return theauth;
}
