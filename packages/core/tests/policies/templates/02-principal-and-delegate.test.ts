/**
 * Tests for template 02 — principal and delegated agent.
 */

import { eq } from "drizzle-orm";
import { beforeEach, describe, expect, it } from "vitest";
import {
	delegatedPermissions,
	principalPermissions,
} from "../../../../../docs/policies/templates/02-principal-and-delegate/policy.js";
import type { Database } from "../../../src/db/database.js";
import { createDatabase } from "../../../src/db/database.js";
import { createTables } from "../../../src/db/migrations.js";
import {
	agents,
	delegationChains,
	permissions as permissionsTable,
	users,
} from "../../../src/db/schema.js";
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

describe("template 02 — principal and delegated agent", () => {
	let db: Database;

	beforeEach(async () => {
		db = await makeDb();
		await seedUser(db, "user-1");
		await seedAgent(db, "principal", "user-1");
		await seedAgent(db, "delegate", "user-1");

		// Seed principal direct permissions
		for (let i = 0; i < principalPermissions.length; i++) {
			const perm = principalPermissions[i];
			if (!perm) continue;
			await db.insert(permissionsTable).values({
				id: `pp${i}`,
				agentId: "principal",
				resource: perm.resource,
				actions: perm.actions,
				constraints: perm.constraints ?? null,
				relation: null,
				createdAt: new Date(),
			});
		}

		// Seed active delegation chain (expires 1 hour from now)
		await db.insert(delegationChains).values({
			id: "chain-1",
			fromAgentId: "principal",
			toAgentId: "delegate",
			permissions: delegatedPermissions.map((p) => ({
				resource: p.resource,
				actions: p.actions,
			})),
			depth: 1,
			maxDepth: 3,
			status: "active",
			expiresAt: new Date(Date.now() + 3_600_000),
			createdAt: new Date(),
		});
	});

	it("allows principal to write", async () => {
		const engine = createPolicyEngine({ db });
		const decision = await engine.evaluate({
			subject: { agentId: "principal" },
			action: "write",
			resource: "reports:monthly",
		});
		expect(decision.allowed).toBe(true);
	});

	it("allows principal to read", async () => {
		const engine = createPolicyEngine({ db });
		const decision = await engine.evaluate({
			subject: { agentId: "principal" },
			action: "read",
			resource: "reports:monthly",
		});
		expect(decision.allowed).toBe(true);
	});

	it("allows delegate to read via active delegation", async () => {
		const engine = createPolicyEngine({ db });
		const decision = await engine.evaluate({
			subject: { agentId: "delegate" },
			action: "read",
			resource: "reports:monthly",
		});
		expect(decision.allowed).toBe(true);
	});

	it("denies delegate from writing (delegated scope is read-only)", async () => {
		const engine = createPolicyEngine({ db });
		const decision = await engine.evaluate({
			subject: { agentId: "delegate" },
			action: "write",
			resource: "reports:monthly",
		});
		expect(decision.allowed).toBe(false);
		expect(decision.reason).toBe(POLICY_ERROR_CODES.NO_MATCHING_PERMISSION);
	});

	it("denies delegate after delegation expires", async () => {
		// Update the chain to be expired
		await db
			.update(delegationChains)
			.set({ expiresAt: new Date(Date.now() - 1000) })
			.where(eq(delegationChains.id, "chain-1"));

		const engine = createPolicyEngine({ db });
		const decision = await engine.evaluate({
			subject: { agentId: "delegate" },
			action: "read",
			resource: "reports:monthly",
		});
		expect(decision.allowed).toBe(false);
	});
});
