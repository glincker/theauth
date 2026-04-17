/**
 * Tests for template 03 — org-scoped agents.
 */

import { beforeEach, describe, expect, it } from "vitest";
import {
	acmeAgentPermissions,
	globexAgentPermissions,
} from "../../../../../docs/policies/templates/03-org-scoped-agents/policy.js";
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

describe("template 03 — org-scoped agents", () => {
	let db: Database;

	beforeEach(async () => {
		db = await makeDb();
		await seedUser(db, "user-acme");
		await seedUser(db, "user-globex");
		await seedAgent(db, "acme-bot", "user-acme");
		await seedAgent(db, "globex-bot", "user-globex");

		for (let i = 0; i < acmeAgentPermissions.length; i++) {
			const perm = acmeAgentPermissions[i];
			if (!perm) continue;
			await db.insert(permissionsTable).values({
				id: `acme-p${i}`,
				agentId: "acme-bot",
				resource: perm.resource,
				actions: perm.actions,
				constraints: null,
				relation: null,
				createdAt: new Date(),
			});
		}

		for (let i = 0; i < globexAgentPermissions.length; i++) {
			const perm = globexAgentPermissions[i];
			if (!perm) continue;
			await db.insert(permissionsTable).values({
				id: `globex-p${i}`,
				agentId: "globex-bot",
				resource: perm.resource,
				actions: perm.actions,
				constraints: null,
				relation: null,
				createdAt: new Date(),
			});
		}
	});

	it("allows acme-bot to read its own org resource", async () => {
		const engine = createPolicyEngine({ db });
		const decision = await engine.evaluate({
			subject: { agentId: "acme-bot", orgId: "acme" },
			action: "read",
			resource: "org:acme:invoices",
		});
		expect(decision.allowed).toBe(true);
	});

	it("allows acme-bot to write its own org resource", async () => {
		const engine = createPolicyEngine({ db });
		const decision = await engine.evaluate({
			subject: { agentId: "acme-bot", orgId: "acme" },
			action: "write",
			resource: "org:acme:documents",
		});
		expect(decision.allowed).toBe(true);
	});

	it("denies acme-bot access to globex resources", async () => {
		const engine = createPolicyEngine({ db });
		const decision = await engine.evaluate({
			subject: { agentId: "acme-bot", orgId: "acme" },
			action: "read",
			resource: "org:globex:invoices",
		});
		expect(decision.allowed).toBe(false);
		expect(decision.reason).toBe(POLICY_ERROR_CODES.NO_MATCHING_PERMISSION);
	});

	it("allows globex-bot to read its own org resource", async () => {
		const engine = createPolicyEngine({ db });
		const decision = await engine.evaluate({
			subject: { agentId: "globex-bot", orgId: "globex" },
			action: "read",
			resource: "org:globex:invoices",
		});
		expect(decision.allowed).toBe(true);
	});

	it("denies globex-bot access to acme resources", async () => {
		const engine = createPolicyEngine({ db });
		const decision = await engine.evaluate({
			subject: { agentId: "globex-bot", orgId: "globex" },
			action: "read",
			resource: "org:acme:documents",
		});
		expect(decision.allowed).toBe(false);
	});

	it("denies an agent with no permissions seeded", async () => {
		await seedUser(db, "user-x");
		await seedAgent(db, "agent-x", "user-x");
		const engine = createPolicyEngine({ db });
		const decision = await engine.evaluate({
			subject: { agentId: "agent-x" },
			action: "read",
			resource: "org:acme:invoices",
		});
		expect(decision.allowed).toBe(false);
	});
});
