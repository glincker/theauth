/**
 * Tri-state policy decisions (allow, deny, escalate), risk tiers, and the
 * opt-in approval request opened by evaluate().
 */

import { beforeEach, describe, expect, it } from "vitest";
import { createApprovalModule } from "../src/approval/approval.js";
import type { Database } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import { agents, permissions as permissionsTable, users } from "../src/db/schema.js";
import { createPolicyEngine } from "../src/policy/engine.js";
import { classifyRisk } from "../src/policy/risk.js";
import type { RiskConfig } from "../src/policy/types.js";
import type { PermissionConstraints } from "../src/types.js";

const RISK: RiskConfig = {
	tiers: [
		{ tier: "medium", when: { minAmount: 100, currency: "USD" }, require: "approval" },
		{ tier: "high", when: { minAmount: 10000 }, require: "step_up" },
		{ tier: "critical", when: { irreversible: true, dataClasses: ["pii"] }, require: "approval" },
		{ tier: "info", when: { dataClasses: ["public"] }, require: "none" },
	],
};

async function setup(constraints?: PermissionConstraints): Promise<Database> {
	const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite");
	const now = new Date();
	await db.insert(users).values({ id: "u1", email: "u1@test", createdAt: now, updatedAt: now });
	await db.insert(agents).values({
		id: "a1",
		ownerId: "u1",
		name: "a1",
		type: "autonomous",
		tokenHash: "h",
		tokenPrefix: "pref0000",
		createdAt: now,
		updatedAt: now,
	});
	await db.insert(permissionsTable).values({
		id: "p1",
		agentId: "a1",
		resource: "tool:pay",
		actions: ["execute"],
		constraints,
		relation: null,
		createdAt: now,
	});
	return db;
}

const input = (risk?: Record<string, unknown>) => ({
	subject: { agentId: "a1" },
	action: "execute",
	resource: "tool:pay",
	context: risk ? { risk } : undefined,
});

describe("policy tri-state decision", () => {
	let db: Database;
	beforeEach(async () => {
		db = await setup();
	});

	it("allow: keeps allowed=true and effect permit", async () => {
		const d = await createPolicyEngine({ db, config: { risk: RISK } }).evaluate(
			input({ amount: 5 }),
		);
		expect(d.decision).toBe("allow");
		expect(d.allowed).toBe(true);
		expect(d.effect).toBe("permit");
		expect(d.escalation).toBeUndefined();
	});

	it("deny: no matching permission", async () => {
		const d = await createPolicyEngine({ db }).evaluate({ ...input(), action: "delete" });
		expect(d.decision).toBe("deny");
		expect(d.allowed).toBe(false);
	});

	it("escalate: risk tier requires approval, allowed is false", async () => {
		const d = await createPolicyEngine({ db, config: { risk: RISK } }).evaluate(
			input({ amount: 500, currency: "USD" }),
		);
		expect(d.decision).toBe("escalate");
		expect(d.effect).toBe("escalate");
		expect(d.allowed).toBe(false);
		expect(d.escalation?.tier).toBe("medium");
		expect(d.escalation?.requirement).toBe("approval");
	});

	it("risk applies on a cache hit and does not poison the cache", async () => {
		const engine = createPolicyEngine({ db, config: { risk: RISK } });
		const low = await engine.evaluate(input({ amount: 1 }));
		const high = await engine.evaluate(input({ amount: 20000 }));
		const low2 = await engine.evaluate(input({ amount: 1 }));
		expect(low.decision).toBe("allow");
		expect(high.decision).toBe("escalate");
		expect(high.cacheHit).toBe(true);
		expect(high.escalation?.requirement).toBe("step_up");
		expect(low2.decision).toBe("allow");
	});

	it("tier none does not escalate", async () => {
		const d = await createPolicyEngine({ db, config: { risk: RISK } }).evaluate(
			input({ dataClass: "public" }),
		);
		expect(d.decision).toBe("allow");
	});

	it("no risk context or config leaves the decision untouched", async () => {
		expect((await createPolicyEngine({ db }).evaluate(input({ amount: 99999 }))).allowed).toBe(
			true,
		);
		expect(
			(await createPolicyEngine({ db, config: { risk: RISK } }).evaluate(input())).allowed,
		).toBe(true);
	});
});

describe("classifyRisk tier mapping", () => {
	it("picks the strongest requirement among matching rules", () => {
		const rule = classifyRisk(RISK, { amount: 50000, currency: "USD" });
		expect(rule?.tier).toBe("high");
		expect(rule?.require).toBe("step_up");
	});

	it("requires all set condition fields", () => {
		expect(classifyRisk(RISK, { irreversible: true, dataClass: "internal" })).toBeUndefined();
		expect(classifyRisk(RISK, { irreversible: true, dataClass: "pii" })?.tier).toBe("critical");
		expect(classifyRisk(RISK, { amount: 500, currency: "EUR" })).toBeUndefined();
	});
});

describe("ABAC requireApproval escalates", () => {
	it("returns escalate instead of deny", async () => {
		const db = await setup({ requireApproval: true });
		const d = await createPolicyEngine({ db }).evaluate(input());
		expect(d.decision).toBe("escalate");
		expect(d.allowed).toBe(false);
		expect(d.escalation?.requirement).toBe("approval");
	});

	it("openApproval opens a pending approval request and returns its id", async () => {
		const db = await setup({ requireApproval: true });
		const approval = createApprovalModule({}, db);
		const engine = createPolicyEngine({ db, approval });

		const d = await engine.evaluate(input(), { openApproval: true });
		const id = d.escalation?.approvalRequestId;
		expect(id).toMatch(/^apr_/);
		const req = await approval.get(id as string);
		expect(req?.status).toBe("pending");
		expect(req?.userId).toBe("u1");

		const plain = await engine.evaluate(input());
		expect(plain.escalation?.approvalRequestId).toBeUndefined();
	});

	it("openApproval on a risk escalation uses the tier", async () => {
		const db = await setup();
		const approval = createApprovalModule({}, db);
		const d = await createPolicyEngine({ db, approval, config: { risk: RISK } }).evaluate(
			input({ amount: 20000 }),
			{ openApproval: true },
		);
		expect(d.escalation?.tier).toBe("high");
		expect(d.escalation?.approvalRequestId).toBeDefined();
	});
});
