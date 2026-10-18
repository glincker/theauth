import { users } from "../../src/db/schema.js";
import type { TheAuth } from "../../src/theauth.js";
import { createTheAuth } from "../../src/theauth.js";

export const SESSION_SECRET = "test-session-secret-that-is-at-least-32-chars!!";
export const BASE = "http://localhost/api/theauth";

export async function makeAuth(): Promise<TheAuth> {
	return createTheAuth({
		database: { provider: "sqlite", url: ":memory:" },
		agents: {
			enabled: true,
			maxPerUser: 1000,
			defaultPermissions: [],
			auditAll: true,
			tokenExpiry: "24h",
		},
		auth: { session: { secret: SESSION_SECRET } },
	});
}

export async function seedUser(auth: TheAuth, id: string): Promise<void> {
	const now = new Date();
	await auth.db
		.insert(users)
		.values({ id, email: `${id}@test.com`, name: id, createdAt: now, updatedAt: now })
		.onConflictDoNothing();
}

export async function sessionToken(auth: TheAuth, userId: string): Promise<string> {
	const sessions = auth.auth.session;
	if (!sessions) throw new Error("session manager missing");
	await seedUser(auth, userId);
	return (await sessions.create(userId)).token;
}

export async function newAgent(auth: TheAuth, ownerId: string, name = "agent") {
	await seedUser(auth, ownerId);
	return auth.agent.create({
		ownerId,
		name,
		type: "autonomous",
		permissions: [{ resource: "docs", actions: ["read"] }],
	});
}
