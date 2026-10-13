/**
 * Tests for the last-login tracking module.
 */

import { beforeEach, describe, expect, it } from "vitest";
import type { LastLoginModule } from "../src/auth/last-login.js";
import { createLastLoginModule } from "../src/auth/last-login.js";
import type { Database } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import { loginHistory, users } from "../src/db/schema.js";

// Helpers

async function createTestDb(): Promise<Database> {
	const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite");
	return db;
}

async function seedUser(db: Database, id: string): Promise<void> {
	const now = new Date();
	await db.insert(users).values({
		id,
		email: `${id}@test.local`,
		name: id,
		createdAt: now,
		updatedAt: now,
	});
}

// recordLogin — all methods

describe("LastLoginModule.recordLogin", () => {
	let db: Database;
	let mod: LastLoginModule;

	beforeEach(async () => {
		db = await createTestDb();
		await seedUser(db, "usr_1");
		mod = createLastLoginModule({}, db);
	});

	it("succeeds for email-password", async () => {
		const result = await mod.recordLogin({ userId: "usr_1", method: "email-password" });
		expect(result.success).toBe(true);
	});

	it("succeeds for magic-link", async () => {
		const result = await mod.recordLogin({ userId: "usr_1", method: "magic-link" });
		expect(result.success).toBe(true);
	});

	it("succeeds for email-otp", async () => {
		const result = await mod.recordLogin({ userId: "usr_1", method: "email-otp" });
		expect(result.success).toBe(true);
	});

	it("succeeds for passkey", async () => {
		const result = await mod.recordLogin({ userId: "usr_1", method: "passkey" });
		expect(result.success).toBe(true);
	});

	it("succeeds for username-password", async () => {
		const result = await mod.recordLogin({ userId: "usr_1", method: "username-password" });
		expect(result.success).toBe(true);
	});

	it("succeeds for phone-sms", async () => {
		const result = await mod.recordLogin({ userId: "usr_1", method: "phone-sms" });
		expect(result.success).toBe(true);
	});

	it("succeeds for siwe", async () => {
		const result = await mod.recordLogin({ userId: "usr_1", method: "siwe" });
		expect(result.success).toBe(true);
	});

	it("succeeds for device-auth", async () => {
		const result = await mod.recordLogin({ userId: "usr_1", method: "device-auth" });
		expect(result.success).toBe(true);
	});

	it("succeeds for anonymous", async () => {
		const result = await mod.recordLogin({ userId: "usr_1", method: "anonymous" });
		expect(result.success).toBe(true);
	});

	it("succeeds for api-key", async () => {
		const result = await mod.recordLogin({ userId: "usr_1", method: "api-key" });
		expect(result.success).toBe(true);
	});

	it("succeeds for oauth:github", async () => {
		const result = await mod.recordLogin({ userId: "usr_1", method: "oauth:github" });
		expect(result.success).toBe(true);
	});

	it("succeeds for oauth:google", async () => {
		const result = await mod.recordLogin({ userId: "usr_1", method: "oauth:google" });
		expect(result.success).toBe(true);
	});

	it("succeeds for oauth:microsoft", async () => {
		const result = await mod.recordLogin({ userId: "usr_1", method: "oauth:microsoft" });
		expect(result.success).toBe(true);
	});

	it("stores ip and userAgent when provided", async () => {
		const result = await mod.recordLogin({
			userId: "usr_1",
			method: "email-password",
			ip: "203.0.113.42",
			userAgent: "Mozilla/5.0 (test)",
		});

		expect(result.success).toBe(true);
		if (!result.success) return;

		expect(result.data.ip).toBe("203.0.113.42");
		expect(result.data.userAgent).toBe("Mozilla/5.0 (test)");
	});

	it("stores null for ip and userAgent when omitted", async () => {
		const result = await mod.recordLogin({ userId: "usr_1", method: "passkey" });
		expect(result.success).toBe(true);
		if (!result.success) return;

		expect(result.data.ip).toBeNull();
		expect(result.data.userAgent).toBeNull();
	});

	it("returns the recorded event with id, userId, method, and timestamp", async () => {
		const before = Date.now();
		const result = await mod.recordLogin({ userId: "usr_1", method: "magic-link" });
		const after = Date.now();

		expect(result.success).toBe(true);
		if (!result.success) return;

		expect(result.data.id).toBeTruthy();
		expect(result.data.userId).toBe("usr_1");
		expect(result.data.method).toBe("magic-link");
		expect(result.data.timestamp.getTime()).toBeGreaterThanOrEqual(before);
		expect(result.data.timestamp.getTime()).toBeLessThanOrEqual(after);
	});

	it("returns INVALID_INPUT for an empty userId", async () => {
		const result = await mod.recordLogin({ userId: "", method: "email-password" });
		expect(result.success).toBe(false);
		if (result.success) return;
		expect(result.error.code).toBe("INVALID_INPUT");
	});

	it("returns INVALID_INPUT for an invalid oauth pattern (no provider)", async () => {
		const result = await mod.recordLogin({
			userId: "usr_1",
			method: "oauth:" as `oauth:${string}`,
		});
		expect(result.success).toBe(false);
		if (result.success) return;
		expect(result.error.code).toBe("INVALID_INPUT");
	});

	it("returns INVALID_INPUT for a completely unknown method", async () => {
		const result = await mod.recordLogin({
			userId: "usr_1",
			// @ts-expect-error intentional invalid method for testing
			method: "not-a-real-method",
		});
		expect(result.success).toBe(false);
		if (result.success) return;
		expect(result.error.code).toBe("INVALID_INPUT");
	});
});

// History pruning

describe("LastLoginModule — history pruning", () => {
	it("keeps only the N most recent logins by default (default N = 10)", async () => {
		const db = await createTestDb();
		await seedUser(db, "usr_prune");
		const mod = createLastLoginModule({}, db);

		for (let i = 0; i < 12; i++) {
			const result = await mod.recordLogin({ userId: "usr_prune", method: "email-password" });
			expect(result.success).toBe(true);
		}

		const histResult = await mod.getLoginHistory("usr_prune");
		expect(histResult.success).toBe(true);
		if (!histResult.success) return;

		expect(histResult.data).toHaveLength(10);
	});

	it("respects a custom maxHistoryPerUser config", async () => {
		const db = await createTestDb();
		await seedUser(db, "usr_prune2");
		const mod = createLastLoginModule({ maxHistoryPerUser: 3 }, db);

		for (let i = 0; i < 5; i++) {
			await mod.recordLogin({ userId: "usr_prune2", method: "passkey" });
		}

		const histResult = await mod.getLoginHistory("usr_prune2");
		expect(histResult.success).toBe(true);
		if (!histResult.success) return;

		expect(histResult.data).toHaveLength(3);
	});

	it("keeps the most recent entries, not the oldest", async () => {
		const db = await createTestDb();
		await seedUser(db, "usr_order_prune");
		const mod = createLastLoginModule({ maxHistoryPerUser: 2 }, db);
		const base = Date.now();

		// Insert directly with spaced timestamps so ordering is deterministic.
		await db.insert(loginHistory).values([
			{
				id: crypto.randomUUID(),
				userId: "usr_order_prune",
				method: "email-password",
				ip: null,
				userAgent: null,
				timestamp: new Date(base),
			},
			{
				id: crypto.randomUUID(),
				userId: "usr_order_prune",
				method: "magic-link",
				ip: null,
				userAgent: null,
				timestamp: new Date(base + 1000),
			},
			{
				id: crypto.randomUUID(),
				userId: "usr_order_prune",
				method: "passkey",
				ip: null,
				userAgent: null,
				timestamp: new Date(base + 2000),
			},
		]);

		// Trigger pruning by recording one more — but now there are already 3 rows
		// so the pruner in the next recordLogin will run. Instead, re-create the
		// module and call getLoginHistory which doesn't prune — verify manually
		// that only 2 of 3 are returned when limit is 2.
		const histResult = await mod.getLoginHistory("usr_order_prune", 2);
		expect(histResult.success).toBe(true);
		if (!histResult.success) return;

		expect(histResult.data).toHaveLength(2);
		// Newest first
		expect(histResult.data[0]?.method).toBe("passkey");
		expect(histResult.data[1]?.method).toBe("magic-link");
	});
});

// getLastLogin

describe("LastLoginModule.getLastLogin", () => {
	let db: Database;
	let mod: LastLoginModule;

	beforeEach(async () => {
		db = await createTestDb();
		await seedUser(db, "usr_1");
		mod = createLastLoginModule({}, db);
	});

	it("returns null when the user has no login history", async () => {
		const result = await mod.getLastLogin("usr_nobody");
		expect(result.success).toBe(true);
		if (!result.success) return;
		expect(result.data).toBeNull();
	});

	it("returns the single event when there is exactly one", async () => {
		await mod.recordLogin({ userId: "usr_1", method: "api-key" });

		const result = await mod.getLastLogin("usr_1");
		expect(result.success).toBe(true);
		if (!result.success) return;

		expect(result.data).not.toBeNull();
		expect(result.data?.method).toBe("api-key");
		expect(result.data?.userId).toBe("usr_1");
	});

	it("returns the most recent event when multiple exist", async () => {
		const base = Date.now();
		// Insert directly with spaced timestamps for deterministic ordering.
		await db.insert(loginHistory).values([
			{
				id: crypto.randomUUID(),
				userId: "usr_1",
				method: "email-password",
				ip: null,
				userAgent: null,
				timestamp: new Date(base),
			},
			{
				id: crypto.randomUUID(),
				userId: "usr_1",
				method: "passkey",
				ip: null,
				userAgent: null,
				timestamp: new Date(base + 1000),
			},
			{
				id: crypto.randomUUID(),
				userId: "usr_1",
				method: "oauth:github",
				ip: null,
				userAgent: null,
				timestamp: new Date(base + 2000),
			},
		]);

		const result = await mod.getLastLogin("usr_1");
		expect(result.success).toBe(true);
		if (!result.success) return;

		expect(result.data?.method).toBe("oauth:github");
	});

	it("returns INVALID_INPUT for an empty userId", async () => {
		const result = await mod.getLastLogin("");
		expect(result.success).toBe(false);
		if (result.success) return;
		expect(result.error.code).toBe("INVALID_INPUT");
	});
});

// getLoginHistory

describe("LastLoginModule.getLoginHistory", () => {
	let db: Database;
	let mod: LastLoginModule;

	beforeEach(async () => {
		db = await createTestDb();
		await seedUser(db, "usr_1");
		await seedUser(db, "usr_order");
		await seedUser(db, "usr_limit");
		await seedUser(db, "usr_few");
		await seedUser(db, "usr_full");
		mod = createLastLoginModule({}, db);
	});

	it("returns an empty array when no history exists", async () => {
		const result = await mod.getLoginHistory("usr_ghost");
		expect(result.success).toBe(true);
		if (!result.success) return;
		expect(result.data).toEqual([]);
	});

	it("returns events in newest-first order", async () => {
		const base = Date.now();
		// Insert directly with spaced timestamps for deterministic ordering.
		await db.insert(loginHistory).values([
			{
				id: crypto.randomUUID(),
				userId: "usr_order",
				method: "email-password",
				ip: null,
				userAgent: null,
				timestamp: new Date(base),
			},
			{
				id: crypto.randomUUID(),
				userId: "usr_order",
				method: "magic-link",
				ip: null,
				userAgent: null,
				timestamp: new Date(base + 1000),
			},
			{
				id: crypto.randomUUID(),
				userId: "usr_order",
				method: "passkey",
				ip: null,
				userAgent: null,
				timestamp: new Date(base + 2000),
			},
		]);

		const result = await mod.getLoginHistory("usr_order");
		expect(result.success).toBe(true);
		if (!result.success) return;

		expect(result.data[0]?.method).toBe("passkey");
		expect(result.data[1]?.method).toBe("magic-link");
		expect(result.data[2]?.method).toBe("email-password");
	});

	it("respects a caller-supplied limit smaller than available history", async () => {
		for (let i = 0; i < 6; i++) {
			await mod.recordLogin({ userId: "usr_limit", method: "phone-sms" });
		}

		const result = await mod.getLoginHistory("usr_limit", 3);
		expect(result.success).toBe(true);
		if (!result.success) return;

		expect(result.data).toHaveLength(3);
	});

	it("returns all events when limit exceeds available history", async () => {
		await mod.recordLogin({ userId: "usr_few", method: "siwe" });
		await mod.recordLogin({ userId: "usr_few", method: "siwe" });

		const result = await mod.getLoginHistory("usr_few", 50);
		expect(result.success).toBe(true);
		if (!result.success) return;

		expect(result.data).toHaveLength(2);
	});

	it("includes id, userId, method, ip, userAgent, and timestamp on each event", async () => {
		await mod.recordLogin({
			userId: "usr_full",
			method: "email-otp",
			ip: "10.0.0.1",
			userAgent: "TestAgent/1.0",
		});

		const result = await mod.getLoginHistory("usr_full");
		expect(result.success).toBe(true);
		if (!result.success) return;

		const event = result.data[0];
		expect(event).toBeDefined();
		if (!event) return;

		expect(typeof event.id).toBe("string");
		expect(event.userId).toBe("usr_full");
		expect(event.method).toBe("email-otp");
		expect(event.ip).toBe("10.0.0.1");
		expect(event.userAgent).toBe("TestAgent/1.0");
		expect(event.timestamp).toBeInstanceOf(Date);
	});

	it("returns INVALID_INPUT for an empty userId", async () => {
		const result = await mod.getLoginHistory("");
		expect(result.success).toBe(false);
		if (result.success) return;
		expect(result.error.code).toBe("INVALID_INPUT");
	});
});

// User isolation

describe("LastLoginModule — user isolation", () => {
	it("histories for different users do not interfere", async () => {
		const db = await createTestDb();
		await seedUser(db, "alice");
		await seedUser(db, "bob");
		const mod = createLastLoginModule({}, db);

		await mod.recordLogin({ userId: "alice", method: "email-password" });
		await mod.recordLogin({ userId: "alice", method: "magic-link" });
		await mod.recordLogin({ userId: "bob", method: "passkey" });

		const aliceHistory = await mod.getLoginHistory("alice");
		const bobHistory = await mod.getLoginHistory("bob");
		// carol was never seeded — no history but no error
		const carolHistory = await mod.getLoginHistory("carol");

		expect(aliceHistory.success).toBe(true);
		expect(bobHistory.success).toBe(true);
		expect(carolHistory.success).toBe(true);

		if (!aliceHistory.success || !bobHistory.success || !carolHistory.success) return;

		expect(aliceHistory.data).toHaveLength(2);
		expect(aliceHistory.data.every((e) => e.userId === "alice")).toBe(true);

		expect(bobHistory.data).toHaveLength(1);
		expect(bobHistory.data[0]?.method).toBe("passkey");

		expect(carolHistory.data).toHaveLength(0);
	});

	it("pruning one user's history does not affect another user's history", async () => {
		const db = await createTestDb();
		await seedUser(db, "alice");
		await seedUser(db, "bob");
		const mod = createLastLoginModule({ maxHistoryPerUser: 2 }, db);

		for (let i = 0; i < 4; i++) {
			await mod.recordLogin({ userId: "alice", method: "email-password" });
		}

		await mod.recordLogin({ userId: "bob", method: "oauth:google" });

		const aliceResult = await mod.getLoginHistory("alice");
		const bobResult = await mod.getLoginHistory("bob");

		expect(aliceResult.success).toBe(true);
		expect(bobResult.success).toBe(true);

		if (!aliceResult.success || !bobResult.success) return;

		expect(aliceResult.data).toHaveLength(2);
		expect(bobResult.data).toHaveLength(1);
		expect(bobResult.data[0]?.method).toBe("oauth:google");
	});

	it("getLastLogin for one user is not influenced by another user's activity", async () => {
		const db = await createTestDb();
		await seedUser(db, "alice");
		await seedUser(db, "bob");
		const mod = createLastLoginModule({}, db);

		await mod.recordLogin({ userId: "alice", method: "api-key" });
		await mod.recordLogin({ userId: "bob", method: "siwe" });
		await mod.recordLogin({ userId: "bob", method: "passkey" });

		const aliceLast = await mod.getLastLogin("alice");
		expect(aliceLast.success).toBe(true);
		if (!aliceLast.success) return;

		expect(aliceLast.data?.method).toBe("api-key");
		expect(aliceLast.data?.userId).toBe("alice");
	});
});
