/**
 * Tests for template 05 — step-up approval for writes.
 */

import { beforeEach, describe, expect, it } from "vitest";
import { stepUpPermissions } from "../../../../../docs/policies/templates/05-step-up-for-writes/policy.js";
import type { Database } from "../../../src/db/database.js";
import { createDatabase } from "../../../src/db/database.js";
import { createTables } from "../../../src/db/migrations.js";
import { agents, permissions as permissionsTable, users } from "../../../src/db/schema.js";
import { createPolicyEngine } from "../../../src/policy/engine.js";
import { POLICY_ERROR_CODES } from "../../../src/policy/types.js";

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

describe("template 05 — step-up approval for writes", () => {
	let db: Database;

	beforeEach(async () => {
		db = await makeDb();
		await seedUser(db, "user-1");
		await seedAgent(db, "data-bot", "user-1");

		for (let i = 0; i < stepUpPermissions.length; i++) {
			const perm = stepUpPermissions[i];
			if (!perm) continue;
			await db.insert(permissionsTable).values({
				id: `p${i}`,
				agentId: "data-bot",
				resource: perm.resource,
				actions: perm.actions,
				constraints: perm.constraints ?? null,
				relation: null,
				createdAt: new Date(),
			});
		}
	});

	it("allows read without approval", async () => {
		const engine = createPolicyEngine({ db });
		const decision = await engine.evaluate({
			subject: { agentId: "data-bot" },
			action: "read",
			resource: "database:records",
		});
		expect(decision.allowed).toBe(true);
		expect(decision.effect).toBe("permit");
	});

	it("denies write with approval-required reason", async () => {
		const engine = createPolicyEngine({ db });
		const decision = await engine.evaluate({
			subject: { agentId: "data-bot" },
			action: "write",
			resource: "database:records",
		});
		expect(decision.allowed).toBe(false);
		expect(decision.reason).toContain("requires human approval");
	});

	it("denies delete with approval-required reason", async () => {
		const engine = createPolicyEngine({ db });
		const decision = await engine.evaluate({
			subject: { agentId: "data-bot" },
			action: "delete",
			resource: "database:records",
		});
		expect(decision.allowed).toBe(false);
		expect(decision.reason).toContain("requires human approval");
	});

	it("denies an action not in the permission set", async () => {
		const engine = createPolicyEngine({ db });
		const decision = await engine.evaluate({
			subject: { agentId: "data-bot" },
			action: "execute",
			resource: "database:records",
		});
		expect(decision.allowed).toBe(false);
		expect(decision.reason).toBe(POLICY_ERROR_CODES.NO_MATCHING_PERMISSION);
	});

	it("denies an unknown agent entirely", async () => {
		await seedUser(db, "user-2");
		await seedAgent(db, "rogue-bot", "user-2");
		const engine = createPolicyEngine({ db });
		const decision = await engine.evaluate({
			subject: { agentId: "rogue-bot" },
			action: "read",
			resource: "database:records",
		});
		expect(decision.allowed).toBe(false);
	});
});
