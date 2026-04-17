/**
 * Integration tests: policy engine wired through createKavach().
 *
 * Verifies that kavach.policy.{evaluate, invalidate, stats} are reachable
 * and produce correct decisions against real in-memory SQLite data.
 */

import { beforeEach, describe, expect, it } from "vitest";
import { agents, permissions as permissionsTable, users } from "../src/db/schema.js";
import type { Kavach } from "../src/kavach.js";
import { createKavach } from "../src/kavach.js";

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────

async function createTestKavach(): Promise<Kavach> {
	return createKavach({
		database: { provider: "sqlite", url: ":memory:" },
		agents: {
			maxPerUser: 10,
			defaultPermissions: [],
			auditAll: false,
			tokenExpiry: "24h",
		},
	});
}

async function seedFixtures(kavach: Kavach): Promise<{ agentId: string; userId: string }> {
	const now = new Date();
	const userId = "u-policy-int";
	const agentId = "a-policy-int";

	await kavach.db.insert(users).values({
		id: userId,
		email: "policy-int@test.local",
		createdAt: now,
		updatedAt: now,
	});

	await kavach.db.insert(agents).values({
		id: agentId,
		ownerId: userId,
		name: "policy-int-agent",
		type: "autonomous",
		tokenHash: "testhash",
		tokenPrefix: "tstpfx00",
		createdAt: now,
		updatedAt: now,
	});

	return { agentId, userId };
}

// ──────────────────────────────────────────────────────────────────────────────
// Suite
// ──────────────────────────────────────────────────────────────────────────────

describe("kavach.policy integration", () => {
	let kavach: Kavach;

	beforeEach(async () => {
		kavach = await createTestKavach();
	});

	it("evaluate() returns a PolicyDecision", async () => {
		const { agentId } = await seedFixtures(kavach);

		const decision = await kavach.policy.evaluate({
			subject: { agentId },
			action: "read",
			resource: "tool:docs",
		});

		expect(decision).toMatchObject({
			allowed: expect.any(Boolean),
			effect: expect.stringMatching(/^(permit|deny|indeterminate)$/),
			reason: expect.any(String),
			cacheHit: false,
			durationMs: expect.any(Number),
		});
	});

	it("evaluate() reflects direct permissions seeded into the DB", async () => {
		const { agentId } = await seedFixtures(kavach);

		await kavach.db.insert(permissionsTable).values({
			id: "perm-int-1",
			agentId,
			resource: "tool:files",
			actions: ["read", "write"],
			createdAt: new Date(),
		});

		const allow = await kavach.policy.evaluate({
			subject: { agentId },
			action: "read",
			resource: "tool:files",
		});
		expect(allow.allowed).toBe(true);
		expect(allow.effect).toBe("permit");

		const deny = await kavach.policy.evaluate({
			subject: { agentId },
			action: "delete",
			resource: "tool:files",
		});
		expect(deny.allowed).toBe(false);
	});

	it("stats() returns hit and miss counters", async () => {
		const { agentId } = await seedFixtures(kavach);

		await kavach.db.insert(permissionsTable).values({
			id: "perm-int-2",
			agentId,
			resource: "tool:stats",
			actions: ["read"],
			createdAt: new Date(),
		});

		// First call is a miss
		await kavach.policy.evaluate({
			subject: { agentId },
			action: "read",
			resource: "tool:stats",
		});

		// Second call is a cache hit
		await kavach.policy.evaluate({
			subject: { agentId },
			action: "read",
			resource: "tool:stats",
		});

		const s = kavach.policy.stats();
		expect(s.misses).toBe(1);
		expect(s.hits).toBe(1);
		expect(s.size).toBe(1);
		expect(typeof s.evictions).toBe("number");
	});

	it("invalidate({ agentId }) clears entries for that agent", async () => {
		const { agentId } = await seedFixtures(kavach);

		await kavach.db.insert(permissionsTable).values({
			id: "perm-int-3",
			agentId,
			resource: "tool:invalidate",
			actions: ["read"],
			createdAt: new Date(),
		});

		// Populate the cache
		await kavach.policy.evaluate({
			subject: { agentId },
			action: "read",
			resource: "tool:invalidate",
		});
		expect(kavach.policy.stats().size).toBe(1);

		// Invalidate by agentId
		kavach.policy.invalidate({ agentId });
		expect(kavach.policy.stats().size).toBe(0);

		// Next call is a fresh miss (not a hit)
		const fresh = await kavach.policy.evaluate({
			subject: { agentId },
			action: "read",
			resource: "tool:invalidate",
		});
		expect(fresh.cacheHit).toBe(false);
	});
});
