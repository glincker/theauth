import { eq } from "drizzle-orm";
import { describe, expect, it } from "vitest";
import { auditLogs, delegationChains, users } from "../src/db/schema.js";
import type { DecisionRow } from "../src/policy-shrink/index.js";
import {
	analyzeUsage,
	previewPolicyChange,
	readDecisionRows,
	suggestShrink,
	verifyShrink,
} from "../src/policy-shrink/index.js";
import type { TheAuth } from "../src/theauth.js";
import { createTheAuth } from "../src/theauth.js";

const T0 = new Date("2026-10-01T00:00:00Z");
const NO_GRANT = 'No permission grants agent "a" access to "x" on "y"';

async function setup(): Promise<TheAuth> {
	const theauth = await createTheAuth({
		database: { provider: "sqlite", url: ":memory:" },
		agents: { auditAll: true },
	});
	await theauth.db.insert(users).values({
		id: "user-1",
		email: "shrink@example.com",
		name: "Shrink",
		createdAt: new Date(),
		updatedAt: new Date(),
	});
	return theauth;
}

let n = 0;
async function log(
	theauth: TheAuth,
	agentId: string,
	action: string,
	resource: string,
	result: "allowed" | "denied" | "rate_limited" = "allowed",
	extra: { reason?: string; at?: Date; delegationChain?: string[] } = {},
): Promise<void> {
	n++;
	await theauth.db.insert(auditLogs).values({
		id: `row-${String(n).padStart(6, "0")}`,
		agentId,
		userId: "user-1",
		action,
		resource,
		parameters: {},
		result,
		reason: extra.reason ?? null,
		durationMs: 1,
		cacheHit: false,
		timestamp: extra.at ?? new Date(T0.getTime() + n * 1000),
		delegationChain: extra.delegationChain ?? null,
	});
}

describe("analyzeUsage against the database", () => {
	it("returns grants as unused for an agent with no rows", async () => {
		const theauth = await setup();
		const a = await theauth.agent.create({
			ownerId: "user-1",
			name: "idle",
			type: "service",
			permissions: [{ resource: "tool:a", actions: ["read"] }],
		});
		const res = await analyzeUsage(theauth.db, a.id, {});
		expect(res.used).toEqual([]);
		expect(res.unused).toEqual([{ resource: "tool:a", actions: ["read"] }]);
		expect(res.evidence.rowsScanned).toBe(0);
	});

	it("separates used from unused using allowed rows, and ignores other-cause denials as non-use", async () => {
		const theauth = await setup();
		const a = await theauth.agent.create({
			ownerId: "user-1",
			name: "worker",
			type: "service",
			permissions: [
				{ resource: "mcp:github:*", actions: ["read", "write"] },
				{ resource: "tool:db", actions: ["query"] },
				{ resource: "tool:mail", actions: ["send"] },
			],
		});
		await log(theauth, a.id, "read", "mcp:github:repos");
		await log(theauth, a.id, "read", "mcp:github:repos");
		await log(theauth, a.id, "send", "tool:mail", "rate_limited", {
			reason: "Rate limit exceeded",
		});
		await log(theauth, a.id, "delete", "tool:db", "denied", { reason: NO_GRANT });

		const res = await analyzeUsage(theauth.db, a.id, {});
		expect(res.used).toHaveLength(1);
		expect(res.used[0]?.count).toBe(2);
		expect(res.attemptedOnly).toEqual([{ resource: "tool:mail", actions: ["send"] }]);
		expect(res.unused.map((p) => `${p.resource}:${p.actions[0]}`)).toEqual([
			"mcp:github:*:write",
			"tool:db:query",
		]);
		expect(res.evidence).toMatchObject({ allowedRows: 2, noGrantDenials: 1, otherDenials: 1 });

		const s = suggestShrink(res);
		expect(s.keep).toEqual([
			{ resource: "mcp:github:*", actions: ["read"] },
			{ resource: "tool:mail", actions: ["send"] },
		]);
		const proof = await previewPolicyChange(theauth.db, a.id, s.keep, {});
		expect(proof.newlyDeniedCount).toBe(0);
		expect(proof.rowsScanned).toBe(4);
	});

	it("honours the since window", async () => {
		const theauth = await setup();
		const a = await theauth.agent.create({
			ownerId: "user-1",
			name: "windowed",
			type: "service",
			permissions: [{ resource: "tool:a", actions: ["read"] }],
		});
		await log(theauth, a.id, "read", "tool:a", "allowed", {
			at: new Date("2026-01-01T00:00:00Z"),
		});
		const res = await analyzeUsage(theauth.db, a.id, { since: new Date("2026-06-01T00:00:00Z") });
		expect(res.used).toEqual([]);
		const all = await analyzeUsage(theauth.db, a.id, {});
		expect(all.used).toHaveLength(1);
	});

	it("attributes delegated use to the delegation chain and drops expired grants", async () => {
		const theauth = await setup();
		const parent = await theauth.agent.create({
			ownerId: "user-1",
			name: "parent",
			type: "service",
			permissions: [{ resource: "tool:*", actions: ["read", "write"] }],
		});
		const child = await theauth.agent.create({
			ownerId: "user-1",
			name: "child",
			type: "delegated",
			permissions: [{ resource: "tool:own", actions: ["read"] }],
		});
		const live = await theauth.delegate({
			fromAgent: parent.id,
			toAgent: child.id,
			permissions: [{ resource: "tool:shared", actions: ["read", "write"] }],
			expiresAt: new Date(Date.now() + 3600_000),
		});
		const stale = await theauth.delegate({
			fromAgent: parent.id,
			toAgent: child.id,
			permissions: [{ resource: "tool:old", actions: ["read"] }],
			expiresAt: new Date(Date.now() + 3600_000),
		});
		await theauth.db
			.update(delegationChains)
			.set({ expiresAt: new Date(Date.now() - 1000) })
			.where(eq(delegationChains.id, stale.id));

		await log(theauth, child.id, "read", "tool:shared", "allowed", { delegationChain: [live.id] });
		await log(theauth, child.id, "read", "tool:old");

		const res = await analyzeUsage(theauth.db, child.id, {});
		expect(res.granted.map((p) => p.resource)).not.toContain("tool:old");
		expect(res.used).toHaveLength(1);
		expect(res.used[0]?.via).toEqual([live.id]);
		expect(res.uncovered).toEqual([{ action: "read", resource: "tool:old", count: 1 }]);
		expect(res.unused.map((p) => `${p.resource}:${p.actions[0]}`).sort()).toEqual([
			"tool:own:read",
			"tool:shared:write",
		]);
	});

	it("pages large windows without dropping or repeating rows, including shared timestamps", async () => {
		const theauth = await setup();
		const a = await theauth.agent.create({
			ownerId: "user-1",
			name: "busy",
			type: "service",
			permissions: [{ resource: "tool:a", actions: ["read"] }],
		});
		const same = new Date("2026-10-02T00:00:00Z");
		for (let i = 0; i < 53; i++)
			await log(theauth, a.id, "read", "tool:a", "allowed", { at: same });
		const ids: string[] = [];
		let pages = 0;
		for await (const page of readDecisionRows(theauth.db, a.id, { pageSize: 10 })) {
			pages++;
			expect(page.length).toBeLessThanOrEqual(10);
			ids.push(...page.map((r) => r.id));
		}
		expect(pages).toBe(6);
		expect(new Set(ids).size).toBe(53);
		const res = await analyzeUsage(theauth.db, a.id, { pageSize: 7 });
		expect(res.used[0]?.count).toBe(53);
	});

	it("previewPolicyChange shows which recorded decisions would flip for a widening too", async () => {
		const theauth = await setup();
		const a = await theauth.agent.create({
			ownerId: "user-1",
			name: "preview",
			type: "service",
			permissions: [{ resource: "tool:a", actions: ["read"] }],
		});
		await log(theauth, a.id, "read", "tool:a");
		await log(theauth, a.id, "write", "tool:a", "denied", { reason: NO_GRANT });
		const wide = [{ resource: "tool:a", actions: ["*"] }];
		const report = await previewPolicyChange(theauth.db, a.id, wide, {});
		expect(report.newlyDeniedCount).toBe(0);
		expect(report.wouldAlsoAllowPreviouslyDenied.map((r) => r.action)).toEqual(["write"]);
		const rows: DecisionRow[] = [];
		for await (const page of readDecisionRows(theauth.db, a.id)) rows.push(...page);
		expect(verifyShrink(rows, wide).wouldAlsoAllowCount).toBe(1);
	});
});
