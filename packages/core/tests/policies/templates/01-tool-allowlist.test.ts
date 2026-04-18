/**
 * Tests for template 01 — tool allowlist.
 */

import { beforeEach, describe, expect, it } from "vitest";
import { toolAllowlistPermissions } from "../../../../../docs/policies/templates/01-tool-allowlist/policy.js";
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

describe("template 01 — tool allowlist", () => {
	let db: Database;

	beforeEach(async () => {
		db = await makeDb();
		await seedUser(db, "user-1");
		await seedAgent(db, "agent-1", "user-1");

		// Seed the allowlist permissions into the DB
		for (let i = 0; i < toolAllowlistPermissions.length; i++) {
			const perm = toolAllowlistPermissions[i];
			if (!perm) continue;
			await db.insert(permissionsTable).values({
				id: `p${i}`,
				agentId: "agent-1",
				resource: perm.resource,
				actions: perm.actions,
				constraints: perm.constraints ?? null,
				relation: null,
				createdAt: new Date(),
			});
		}
	});

	it("allows a tool that is on the allowlist", async () => {
		const engine = createPolicyEngine({ db });
		const decision = await engine.evaluate({
			subject: { agentId: "agent-1" },
			action: "execute",
			resource: "tool:web_search",
		});
		expect(decision.allowed).toBe(true);
		expect(decision.effect).toBe("permit");
	});

	it("allows every tool on the allowlist", async () => {
		const engine = createPolicyEngine({ db });
		for (const perm of toolAllowlistPermissions) {
			const decision = await engine.evaluate({
				subject: { agentId: "agent-1" },
				action: "execute",
				resource: perm.resource,
			});
			expect(decision.allowed, `expected allow for ${perm.resource}`).toBe(true);
		}
	});

	it("denies a tool that is not on the allowlist", async () => {
		const engine = createPolicyEngine({ db });
		const decision = await engine.evaluate({
			subject: { agentId: "agent-1" },
			action: "execute",
			resource: "tool:shell_exec",
		});
		expect(decision.allowed).toBe(false);
		expect(decision.effect).toBe("indeterminate");
		expect(decision.reason).toBe(POLICY_ERROR_CODES.NO_MATCHING_PERMISSION);
	});

	it("denies an unlisted action on a listed tool", async () => {
		const engine = createPolicyEngine({ db });
		const decision = await engine.evaluate({
			subject: { agentId: "agent-1" },
			action: "write",
			resource: "tool:file_read",
		});
		expect(decision.allowed).toBe(false);
	});

	it("denies an unknown agent (no permissions seeded)", async () => {
		await seedUser(db, "user-2");
		await seedAgent(db, "agent-unknown", "user-2");
		const engine = createPolicyEngine({ db });
		const decision = await engine.evaluate({
			subject: { agentId: "agent-unknown" },
			action: "execute",
			resource: "tool:web_search",
		});
		expect(decision.allowed).toBe(false);
		expect(decision.reason).toBe(POLICY_ERROR_CODES.NO_MATCHING_PERMISSION);
	});

	it("returns INVALID_INPUT when subject is empty", async () => {
		const engine = createPolicyEngine({ db });
		const decision = await engine.evaluate({
			subject: {},
			action: "execute",
			resource: "tool:web_search",
		});
		expect(decision.allowed).toBe(false);
		expect(decision.reason).toBe(POLICY_ERROR_CODES.INVALID_INPUT);
	});
});
