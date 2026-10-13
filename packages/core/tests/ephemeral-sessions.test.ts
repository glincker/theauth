import { beforeEach, describe, expect, it } from "vitest";
import type { EphemeralSessionModule } from "../src/auth/ephemeral-sessions.js";
import { createEphemeralSessionModule } from "../src/auth/ephemeral-sessions.js";
import type { Database } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import * as schema from "../src/db/schema.js";

// Test harness

async function createTestDb(): Promise<Database> {
	const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite");
	return db;
}

async function seedUser(db: Database, id = "user-1"): Promise<void> {
	db.insert(schema.users)
		.values({
			id,
			email: `${id}@example.com`,
			name: "Test User",
			createdAt: new Date(),
			updatedAt: new Date(),
		})
		.run();
}

function makeModule(
	db: Database,
	opts: Partial<{
		defaultTtlSeconds: number;
		maxTtlSeconds: number;
		autoRevokeOnExpiry: boolean;
		auditGrouping: boolean;
	}> = {},
): EphemeralSessionModule {
	return createEphemeralSessionModule({
		db,
		defaultTtlSeconds: 300,
		maxTtlSeconds: 3600,
		autoRevokeOnExpiry: true,
		auditGrouping: true,
		...opts,
	});
}

const BASE_PERMS = [{ resource: "tool:browser", actions: ["navigate", "click"] }];

// Session creation

describe("createSession", () => {
	let db: Database;
	let mod: EphemeralSessionModule;

	beforeEach(async () => {
		db = await createTestDb();
		await seedUser(db);
		mod = makeModule(db);
	});

	it("creates a session with default TTL", async () => {
		const result = await mod.createSession({
			ownerId: "user-1",
			permissions: BASE_PERMS,
		});

		expect(result.success).toBe(true);
		if (!result.success) return;

		const session = result.data;
		expect(session.sessionId).toBeDefined();
		expect(session.agentId).toBeDefined();
		expect(session.token).toMatch(/^kveph_/);
		expect(session.status).toBe("active");
		expect(session.actionsUsed).toBe(0);
		expect(session.maxActions).toBeNull();
		// Default 300s TTL → expiresAt should be roughly 5 min from now
		expect(session.expiresAt.getTime()).toBeGreaterThan(Date.now() + 290_000);
		expect(session.expiresAt.getTime()).toBeLessThan(Date.now() + 310_000);
	});

	it("creates a session with a custom TTL", async () => {
		const result = await mod.createSession({
			ownerId: "user-1",
			permissions: BASE_PERMS,
			ttlSeconds: 60,
		});

		expect(result.success).toBe(true);
		if (!result.success) return;

		expect(result.data.expiresAt.getTime()).toBeGreaterThan(Date.now() + 55_000);
		expect(result.data.expiresAt.getTime()).toBeLessThan(Date.now() + 65_000);
	});

	it("creates a session with a maxActions limit", async () => {
		const result = await mod.createSession({
			ownerId: "user-1",
			permissions: BASE_PERMS,
			maxActions: 5,
		});

		expect(result.success).toBe(true);
		if (!result.success) return;

		expect(result.data.maxActions).toBe(5);
	});

	it("creates a session with a custom name", async () => {
		const result = await mod.createSession({
			ownerId: "user-1",
			name: "browser-task",
			permissions: BASE_PERMS,
		});

		expect(result.success).toBe(true);
	});

	it("assigns an auditGroupId when auditGrouping is enabled", async () => {
		const result = await mod.createSession({
			ownerId: "user-1",
			permissions: BASE_PERMS,
		});

		expect(result.success).toBe(true);
		if (!result.success) return;
		expect(result.data.auditGroupId).toBeDefined();
		expect(result.data.auditGroupId).not.toBe("");
	});

	it("returns a token that starts with kveph_", async () => {
		const result = await mod.createSession({
			ownerId: "user-1",
			permissions: BASE_PERMS,
		});

		expect(result.success).toBe(true);
		if (!result.success) return;
		expect(result.data.token).toMatch(/^kveph_/);
	});

	it("rejects TTL that exceeds maxTtlSeconds", async () => {
		const result = await mod.createSession({
			ownerId: "user-1",
			permissions: BASE_PERMS,
			ttlSeconds: 7200, // 2 hours, max is 1 hour
		});

		expect(result.success).toBe(false);
		if (result.success) return;
		expect(result.error.code).toBe("TTL_EXCEEDS_MAX");
	});

	it("rejects empty permissions array", async () => {
		const result = await mod.createSession({
			ownerId: "user-1",
			permissions: [],
		});

		expect(result.success).toBe(false);
		if (result.success) return;
		expect(result.error.code).toBe("VALIDATION_ERROR");
	});

	it("accepts metadata on the session", async () => {
		const result = await mod.createSession({
			ownerId: "user-1",
			permissions: BASE_PERMS,
			metadata: { task: "fill-form", jobId: "job-99" },
		});

		expect(result.success).toBe(true);
	});

	it("different sessions get different tokens", async () => {
		const a = await mod.createSession({ ownerId: "user-1", permissions: BASE_PERMS });
		const b = await mod.createSession({ ownerId: "user-1", permissions: BASE_PERMS });

		expect(a.success).toBe(true);
		expect(b.success).toBe(true);
		if (!a.success || !b.success) return;
		expect(a.data.token).not.toBe(b.data.token);
	});
});

// Token validation

describe("validateSession", () => {
	let db: Database;
	let mod: EphemeralSessionModule;

	beforeEach(async () => {
		db = await createTestDb();
		await seedUser(db);
		mod = makeModule(db);
	});

	it("validates a fresh token", async () => {
		const created = await mod.createSession({ ownerId: "user-1", permissions: BASE_PERMS });
		expect(created.success).toBe(true);
		if (!created.success) return;

		const validated = await mod.validateSession(created.data.token);
		expect(validated.success).toBe(true);
		if (!validated.success) return;

		expect(validated.data.sessionId).toBe(created.data.sessionId);
		expect(validated.data.agentId).toBe(created.data.agentId);
		expect(validated.data.expiresIn).toBeGreaterThan(0);
		expect(validated.data.remainingActions).toBeNull(); // no limit set
	});

	it("returns remainingActions when maxActions is set", async () => {
		const created = await mod.createSession({
			ownerId: "user-1",
			permissions: BASE_PERMS,
			maxActions: 10,
		});
		expect(created.success).toBe(true);
		if (!created.success) return;

		const validated = await mod.validateSession(created.data.token);
		expect(validated.success).toBe(true);
		if (!validated.success) return;
		expect(validated.data.remainingActions).toBe(10);
	});

	it("rejects a completely unknown token", async () => {
		const result = await mod.validateSession("kveph_thisisnotarealtoken123456789");
		expect(result.success).toBe(false);
		if (result.success) return;
		expect(result.error.code).toBe("SESSION_NOT_FOUND");
	});

	it("rejects a revoked session", async () => {
		const created = await mod.createSession({ ownerId: "user-1", permissions: BASE_PERMS });
		expect(created.success).toBe(true);
		if (!created.success) return;

		await mod.revokeSession(created.data.sessionId);

		const validated = await mod.validateSession(created.data.token);
		expect(validated.success).toBe(false);
		if (validated.success) return;
		expect(validated.error.code).toBe("SESSION_REVOKED");
	});

	it("returns the auditGroupId in the result", async () => {
		const created = await mod.createSession({ ownerId: "user-1", permissions: BASE_PERMS });
		expect(created.success).toBe(true);
		if (!created.success) return;

		const validated = await mod.validateSession(created.data.token);
		expect(validated.success).toBe(true);
		if (!validated.success) return;
		expect(validated.data.auditGroupId).toBe(created.data.auditGroupId);
	});
});

// Action consumption

describe("consumeAction", () => {
	let db: Database;
	let mod: EphemeralSessionModule;

	beforeEach(async () => {
		db = await createTestDb();
		await seedUser(db);
		mod = makeModule(db);
	});

	it("decrements remainingActions on each call", async () => {
		const created = await mod.createSession({
			ownerId: "user-1",
			permissions: BASE_PERMS,
			maxActions: 3,
		});
		expect(created.success).toBe(true);
		if (!created.success) return;

		const r1 = await mod.consumeAction(created.data.token);
		expect(r1.success).toBe(true);
		if (!r1.success) return;
		expect(r1.data.actionsRemaining).toBe(2);

		const r2 = await mod.consumeAction(created.data.token);
		expect(r2.success).toBe(true);
		if (!r2.success) return;
		expect(r2.data.actionsRemaining).toBe(1);
	});

	it("returns null for actionsRemaining when no limit is set", async () => {
		const created = await mod.createSession({ ownerId: "user-1", permissions: BASE_PERMS });
		expect(created.success).toBe(true);
		if (!created.success) return;

		const r = await mod.consumeAction(created.data.token);
		expect(r.success).toBe(true);
		if (!r.success) return;
		expect(r.data.actionsRemaining).toBeNull();
	});

	it("exhausts the session when the budget is spent", async () => {
		const created = await mod.createSession({
			ownerId: "user-1",
			permissions: BASE_PERMS,
			maxActions: 2,
		});
		expect(created.success).toBe(true);
		if (!created.success) return;

		await mod.consumeAction(created.data.token);
		const last = await mod.consumeAction(created.data.token);
		// The last action that exactly hits the budget should succeed
		expect(last.success).toBe(true);
		if (!last.success) return;
		expect(last.data.actionsRemaining).toBe(0);

		// A further consume should fail
		const over = await mod.consumeAction(created.data.token);
		expect(over.success).toBe(false);
		if (over.success) return;
		expect(over.error.code).toBe("SESSION_EXHAUSTED");
	});

	it("refuses action on a revoked session", async () => {
		const created = await mod.createSession({ ownerId: "user-1", permissions: BASE_PERMS });
		expect(created.success).toBe(true);
		if (!created.success) return;

		await mod.revokeSession(created.data.sessionId);

		const r = await mod.consumeAction(created.data.token);
		expect(r.success).toBe(false);
		if (r.success) return;
		expect(r.error.code).toBe("SESSION_REVOKED");
	});

	it("refuses action on an unknown token", async () => {
		const r = await mod.consumeAction("kveph_unknowntoken");
		expect(r.success).toBe(false);
		if (r.success) return;
		expect(r.error.code).toBe("SESSION_NOT_FOUND");
	});

	it("validates session still active after partial consumption", async () => {
		const created = await mod.createSession({
			ownerId: "user-1",
			permissions: BASE_PERMS,
			maxActions: 5,
		});
		expect(created.success).toBe(true);
		if (!created.success) return;

		await mod.consumeAction(created.data.token);
		await mod.consumeAction(created.data.token);

		const validated = await mod.validateSession(created.data.token);
		expect(validated.success).toBe(true);
		if (!validated.success) return;
		expect(validated.data.remainingActions).toBe(3);
	});
});

// Session revocation

describe("revokeSession", () => {
	let db: Database;
	let mod: EphemeralSessionModule;

	beforeEach(async () => {
		db = await createTestDb();
		await seedUser(db);
		mod = makeModule(db);
	});

	it("revokes an active session", async () => {
		const created = await mod.createSession({ ownerId: "user-1", permissions: BASE_PERMS });
		expect(created.success).toBe(true);
		if (!created.success) return;

		const revoked = await mod.revokeSession(created.data.sessionId);
		expect(revoked.success).toBe(true);

		const validated = await mod.validateSession(created.data.token);
		expect(validated.success).toBe(false);
	});

	it("is idempotent — revoking twice does not error", async () => {
		const created = await mod.createSession({ ownerId: "user-1", permissions: BASE_PERMS });
		expect(created.success).toBe(true);
		if (!created.success) return;

		await mod.revokeSession(created.data.sessionId);
		const second = await mod.revokeSession(created.data.sessionId);
		expect(second.success).toBe(true);
	});

	it("returns SESSION_NOT_FOUND for an unknown sessionId", async () => {
		const result = await mod.revokeSession("nonexistent-session-id");
		expect(result.success).toBe(false);
		if (result.success) return;
		expect(result.error.code).toBe("SESSION_NOT_FOUND");
	});
});

// Listing active sessions

describe("listActiveSessions", () => {
	let db: Database;
	let mod: EphemeralSessionModule;

	beforeEach(async () => {
		db = await createTestDb();
		await seedUser(db);
		await seedUser(db, "user-2");
		mod = makeModule(db);
	});

	it("returns all active sessions for a user", async () => {
		await mod.createSession({ ownerId: "user-1", permissions: BASE_PERMS });
		await mod.createSession({ ownerId: "user-1", permissions: BASE_PERMS });

		const result = await mod.listActiveSessions("user-1");
		expect(result.success).toBe(true);
		if (!result.success) return;
		expect(result.data).toHaveLength(2);
	});

	it("returns only sessions for the specified owner", async () => {
		await mod.createSession({ ownerId: "user-1", permissions: BASE_PERMS });
		await mod.createSession({ ownerId: "user-2", permissions: BASE_PERMS });

		const result = await mod.listActiveSessions("user-1");
		expect(result.success).toBe(true);
		if (!result.success) return;
		expect(result.data).toHaveLength(1);
		expect(result.data[0]?.sessionId).toBeDefined();
	});

	it("excludes revoked sessions", async () => {
		const created = await mod.createSession({ ownerId: "user-1", permissions: BASE_PERMS });
		expect(created.success).toBe(true);
		if (!created.success) return;

		await mod.revokeSession(created.data.sessionId);

		const result = await mod.listActiveSessions("user-1");
		expect(result.success).toBe(true);
		if (!result.success) return;
		expect(result.data).toHaveLength(0);
	});

	it("returns an empty array for a user with no sessions", async () => {
		const result = await mod.listActiveSessions("user-2");
		expect(result.success).toBe(true);
		if (!result.success) return;
		expect(result.data).toHaveLength(0);
	});

	it("never exposes the raw token in listed sessions", async () => {
		await mod.createSession({ ownerId: "user-1", permissions: BASE_PERMS });

		const result = await mod.listActiveSessions("user-1");
		expect(result.success).toBe(true);
		if (!result.success) return;
		for (const session of result.data) {
			expect(session.token).toBe("");
		}
	});
});

// Cleanup

describe("cleanupExpired", () => {
	let db: Database;

	beforeEach(async () => {
		db = await createTestDb();
		await seedUser(db);
	});

	it("returns zero when there is nothing to clean up", async () => {
		const mod = makeModule(db);
		// Create a live session
		await mod.createSession({ ownerId: "user-1", permissions: BASE_PERMS });

		const result = await mod.cleanupExpired();
		expect(result.success).toBe(true);
		if (!result.success) return;
		expect(result.data.count).toBe(0);
	});

	it("cleans up sessions whose TTL has lapsed", async () => {
		// Use a very short TTL so we can simulate expiry by manipulating the DB row
		const mod = makeModule(db, { defaultTtlSeconds: 300 });
		const created = await mod.createSession({ ownerId: "user-1", permissions: BASE_PERMS });
		expect(created.success).toBe(true);
		if (!created.success) return;

		// Back-date the expires_at to the past
		const past = new Date(Date.now() - 1000);
		db.update(schema.ephemeralSessions)
			.set({ expiresAt: past })
			.where(
				// @ts-expect-error — accessing schema directly for test manipulation
				schema.ephemeralSessions.id.equals ? undefined : undefined,
			)
			.run();

		// Use drizzle directly
		const { eq } = await import("drizzle-orm");
		db.update(schema.ephemeralSessions)
			.set({ expiresAt: past })
			.where(eq(schema.ephemeralSessions.id, created.data.sessionId))
			.run();

		const result = await mod.cleanupExpired();
		expect(result.success).toBe(true);
		if (!result.success) return;
		expect(result.data.count).toBe(1);
	});

	it("does not re-clean already-expired sessions", async () => {
		const mod = makeModule(db);
		const created = await mod.createSession({ ownerId: "user-1", permissions: BASE_PERMS });
		expect(created.success).toBe(true);
		if (!created.success) return;

		// Back-date and run cleanup once
		const { eq } = await import("drizzle-orm");
		const past = new Date(Date.now() - 1000);
		db.update(schema.ephemeralSessions)
			.set({ expiresAt: past })
			.where(eq(schema.ephemeralSessions.id, created.data.sessionId))
			.run();

		await mod.cleanupExpired();

		// Second run should find zero because they are already "expired"
		const second = await mod.cleanupExpired();
		expect(second.success).toBe(true);
		if (!second.success) return;
		expect(second.data.count).toBe(0);
	});
});

// Audit grouping

describe("audit grouping", () => {
	let db: Database;

	beforeEach(async () => {
		db = await createTestDb();
		await seedUser(db);
	});

	it("returns consistent auditGroupId across validate calls for the same session", async () => {
		const mod = makeModule(db, { auditGrouping: true });
		const created = await mod.createSession({ ownerId: "user-1", permissions: BASE_PERMS });
		expect(created.success).toBe(true);
		if (!created.success) return;

		const v1 = await mod.validateSession(created.data.token);
		const v2 = await mod.validateSession(created.data.token);

		expect(v1.success).toBe(true);
		expect(v2.success).toBe(true);
		if (!v1.success || !v2.success) return;
		expect(v1.data.auditGroupId).toBe(v2.data.auditGroupId);
	});

	it("each session gets a distinct auditGroupId", async () => {
		const mod = makeModule(db, { auditGrouping: true });
		const s1 = await mod.createSession({ ownerId: "user-1", permissions: BASE_PERMS });
		const s2 = await mod.createSession({ ownerId: "user-1", permissions: BASE_PERMS });

		expect(s1.success).toBe(true);
		expect(s2.success).toBe(true);
		if (!s1.success || !s2.success) return;
		expect(s1.data.auditGroupId).not.toBe(s2.data.auditGroupId);
	});
});

// Auto-revoke on expiry/exhaustion

describe("autoRevokeOnExpiry", () => {
	let db: Database;

	beforeEach(async () => {
		db = await createTestDb();
		await seedUser(db);
	});

	it("revokes the underlying agent when the session is explicitly revoked", async () => {
		const mod = makeModule(db, { autoRevokeOnExpiry: true });
		const created = await mod.createSession({ ownerId: "user-1", permissions: BASE_PERMS });
		expect(created.success).toBe(true);
		if (!created.success) return;

		await mod.revokeSession(created.data.sessionId);

		const { eq } = await import("drizzle-orm");
		const agentRows = await db
			.select()
			.from(schema.agents)
			.where(eq(schema.agents.id, created.data.agentId));

		expect(agentRows[0]?.status).toBe("revoked");
	});

	it("revokes the underlying agent when the action budget is exhausted", async () => {
		const mod = makeModule(db, { autoRevokeOnExpiry: true });
		const created = await mod.createSession({
			ownerId: "user-1",
			permissions: BASE_PERMS,
			maxActions: 1,
		});
		expect(created.success).toBe(true);
		if (!created.success) return;

		// Consume the only allowed action
		await mod.consumeAction(created.data.token);

		const { eq } = await import("drizzle-orm");
		const agentRows = await db
			.select()
			.from(schema.agents)
			.where(eq(schema.agents.id, created.data.agentId));

		expect(agentRows[0]?.status).toBe("revoked");
	});
});

// maxActions enforcement edge cases

describe("maxActions edge cases", () => {
	let db: Database;
	let mod: EphemeralSessionModule;

	beforeEach(async () => {
		db = await createTestDb();
		await seedUser(db);
		mod = makeModule(db);
	});

	it("allows exactly maxActions actions", async () => {
		const created = await mod.createSession({
			ownerId: "user-1",
			permissions: BASE_PERMS,
			maxActions: 3,
		});
		expect(created.success).toBe(true);
		if (!created.success) return;

		const results = await Promise.all([
			mod.consumeAction(created.data.token),
			mod.consumeAction(created.data.token),
			mod.consumeAction(created.data.token),
		]);

		// All three should succeed
		for (const r of results) {
			expect(r.success).toBe(true);
		}
	});

	it("blocks the (maxActions + 1)th action", async () => {
		const created = await mod.createSession({
			ownerId: "user-1",
			permissions: BASE_PERMS,
			maxActions: 2,
		});
		expect(created.success).toBe(true);
		if (!created.success) return;

		await mod.consumeAction(created.data.token);
		await mod.consumeAction(created.data.token);

		const blocked = await mod.consumeAction(created.data.token);
		expect(blocked.success).toBe(false);
		if (blocked.success) return;
		expect(blocked.error.code).toBe("SESSION_EXHAUSTED");
	});

	it("session is exhausted after the last action", async () => {
		const created = await mod.createSession({
			ownerId: "user-1",
			permissions: BASE_PERMS,
			maxActions: 1,
		});
		expect(created.success).toBe(true);
		if (!created.success) return;

		await mod.consumeAction(created.data.token);

		// validateSession should now return EXHAUSTED
		const validated = await mod.validateSession(created.data.token);
		expect(validated.success).toBe(false);
		if (validated.success) return;
		expect(validated.error.code).toBe("SESSION_EXHAUSTED");
	});
});
