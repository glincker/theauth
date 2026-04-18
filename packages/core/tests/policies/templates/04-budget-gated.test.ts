/**
 * Tests for template 04 — budget-gated agent.
 */

import { beforeEach, describe, expect, it } from "vitest";
import {
	budgetGatedPermissions,
	MAX_CALLS_PER_HOUR,
} from "../../../../../docs/policies/templates/04-budget-gated/policy.js";
import type { Database } from "../../../src/db/database.js";
import { createDatabase } from "../../../src/db/database.js";
import { createTables } from "../../../src/db/migrations.js";
import {
	agents,
	permissions as permissionsTable,
	rateLimits,
	users,
} from "../../../src/db/schema.js";
import { createPolicyEngine } from "../../../src/policy/engine.js";

async function makeDb(): Promise<Database> {
	const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite");
	return db;
}

async function seedUser(db: Database, id: string): Promise<void> {
	const now = new Date();
	await db.insert(users).values({ id, email: `${id}@test`, createdAt: now, updatedAt: now });
}

async function seedAgent(db: Database, id: string, ownerId: string): Promise<void> {
	const now = new Date();
	await db.insert(agents).values({
		id,
		ownerId,
		name: id,
		type: "autonomous",
		tokenHash: "hash",
		tokenPrefix: "pref0000",
		createdAt: now,
		updatedAt: now,
	});
}

describe("template 04 — budget-gated agent", () => {
	let db: Database;

	beforeEach(async () => {
		db = await makeDb();
		await seedUser(db, "user-1");
		await seedAgent(db, "budget-bot", "user-1");

		for (let i = 0; i < budgetGatedPermissions.length; i++) {
			const perm = budgetGatedPermissions[i];
			if (!perm) continue;
			await db.insert(permissionsTable).values({
				id: `p${i}`,
				agentId: "budget-bot",
				resource: perm.resource,
				actions: perm.actions,
				constraints: perm.constraints ?? null,
				relation: null,
				createdAt: new Date(),
			});
		}
	});

	it("allows calls when the rate-limit window is empty", async () => {
		const engine = createPolicyEngine({ db });
		const decision = await engine.evaluate({
			subject: { agentId: "budget-bot" },
			action: "execute",
			resource: "llm:gateway",
		});
		expect(decision.allowed).toBe(true);
	});

	it("denies once the per-hour cap is reached (pre-seeded window)", async () => {
		// Pre-seed a rate-limit row at exactly MAX_CALLS_PER_HOUR for the current window.
		const windowStart = new Date(Math.floor(Date.now() / (5 * 60 * 1000)) * (5 * 60 * 1000));
		await db.insert(rateLimits).values({
			id: "rl-1",
			agentId: "budget-bot",
			resource: "llm:gateway",
			windowStart,
			count: MAX_CALLS_PER_HOUR,
		});

		const engine = createPolicyEngine({ db });
		const decision = await engine.evaluate({
			subject: { agentId: "budget-bot" },
			action: "execute",
			resource: "llm:gateway",
		});
		expect(decision.allowed).toBe(false);
		expect(decision.reason).toContain("Rate limit exceeded");
	});

	it("does not cache rate-limited decisions", async () => {
		const engine = createPolicyEngine({ db });
		await engine.evaluate({
			subject: { agentId: "budget-bot" },
			action: "execute",
			resource: "llm:gateway",
		});
		// maxCallsPerHour means cache is bypassed
		expect(engine.stats().size).toBe(0);
	});

	it("denies an action not covered by the permission", async () => {
		const engine = createPolicyEngine({ db });
		const decision = await engine.evaluate({
			subject: { agentId: "budget-bot" },
			action: "write",
			resource: "llm:gateway",
		});
		expect(decision.allowed).toBe(false);
	});

	it("denies an unknown agent with no permissions", async () => {
		await seedUser(db, "user-2");
		await seedAgent(db, "other-bot", "user-2");
		const engine = createPolicyEngine({ db });
		const decision = await engine.evaluate({
			subject: { agentId: "other-bot" },
			action: "execute",
			resource: "llm:gateway",
		});
		expect(decision.allowed).toBe(false);
	});
});
