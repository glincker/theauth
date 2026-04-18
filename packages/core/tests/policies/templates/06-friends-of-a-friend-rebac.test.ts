/**
 * Tests for template 06 — ReBAC document sharing.
 */

import { beforeEach, describe, expect, it } from "vitest";
import { rebacDocPermission } from "../../../../../docs/policies/templates/06-friends-of-a-friend-rebac/policy.js";
import { createReBACModule } from "../../../src/auth/rebac.js";
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

describe("template 06 — ReBAC document sharing", () => {
	let db: Database;

	beforeEach(async () => {
		db = await makeDb();
		await seedUser(db, "user-1");
		await seedUser(db, "user-2");
		await seedAgent(db, "viewer-bot", "user-1");
		await seedAgent(db, "outsider-bot", "user-2");

		// Seed the permission row for both agents (same permission definition)
		for (const [agentId, prefix] of [
			["viewer-bot", "vb"],
			["outsider-bot", "ob"],
		] as const) {
			for (let i = 0; i < rebacDocPermission.length; i++) {
				const perm = rebacDocPermission[i];
				if (!perm) continue;
				await db.insert(permissionsTable).values({
					id: `${prefix}-p${i}`,
					agentId,
					resource: perm.resource,
					actions: perm.actions,
					constraints: perm.constraints ?? null,
					relation: perm.relation ?? null,
					createdAt: new Date(),
				});
			}
		}

		// Create the document resource and grant viewer-bot the "viewer" relation
		const rebac = createReBACModule({}, db);
		await rebac.createResource({ id: "42", type: "doc" });
		await rebac.addRelationship({
			subjectType: "agent",
			subjectId: "viewer-bot",
			relation: "viewer",
			objectType: "doc",
			objectId: "42",
		});
		// No tuple for outsider-bot
	});

	it("allows viewer-bot to read the document (tuple exists)", async () => {
		const engine = createPolicyEngine({ db });
		const decision = await engine.evaluate({
			subject: { agentId: "viewer-bot" },
			action: "read",
			resource: "doc:42",
		});
		expect(decision.allowed).toBe(true);
		expect(decision.matchedRelation).toBe("viewer");
	});

	it("denies outsider-bot (no tuple for that agent)", async () => {
		const engine = createPolicyEngine({ db });
		const decision = await engine.evaluate({
			subject: { agentId: "outsider-bot" },
			action: "read",
			resource: "doc:42",
		});
		expect(decision.allowed).toBe(false);
	});

	it("denies when a wildcard resource ID is used", async () => {
		// Seed a wildcard permission row directly to verify the bridge rejects it
		await seedUser(db, "user-3");
		await seedAgent(db, "wildcard-bot", "user-3");
		await db.insert(permissionsTable).values({
			id: "wildcard-p",
			agentId: "wildcard-bot",
			resource: "doc:*",
			actions: ["read"],
			constraints: null,
			relation: "viewer",
			createdAt: new Date(),
		});

		const engine = createPolicyEngine({ db });
		const decision = await engine.evaluate({
			subject: { agentId: "wildcard-bot" },
			action: "read",
			resource: "doc:42",
		});
		// Wildcard resource in permission row does not match the concrete "doc:42"
		// because matchResource("doc:*", "doc:42") returns true but the ReBAC
		// bridge would then receive "doc:42" (not "doc:*"), so the tuple check
		// fires. However, since no tuple exists for wildcard-bot, it denies.
		expect(decision.allowed).toBe(false);
	});

	it("denies read on a different document ID (no tuple for doc:99)", async () => {
		// Seed a permission for the new resource ID (no tuple created)
		await db.insert(permissionsTable).values({
			id: "vb-doc99",
			agentId: "viewer-bot",
			resource: "doc:99",
			actions: ["read"],
			constraints: null,
			relation: "viewer",
			createdAt: new Date(),
		});

		const engine = createPolicyEngine({ db });
		const decision = await engine.evaluate({
			subject: { agentId: "viewer-bot" },
			action: "read",
			resource: "doc:99",
		});
		expect(decision.allowed).toBe(false);
	});

	it("denies when subject has no agentId or userId (invalid input)", async () => {
		const engine = createPolicyEngine({ db });
		const decision = await engine.evaluate({
			subject: {},
			action: "read",
			resource: "doc:42",
		});
		expect(decision.allowed).toBe(false);
		expect(decision.reason).toBe(POLICY_ERROR_CODES.INVALID_INPUT);
	});
});
