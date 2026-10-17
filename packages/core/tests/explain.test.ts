/** explain(): read-only mirror of authorize() with the full reasoning. */
import { describe, expect, it } from "vitest";
import { approvalRequests, auditLogs, rateLimits } from "../src/db/schema.js";
import type { ExplainOptions } from "../src/explain/index.js";
import type { BeforeAuthorizeContext } from "../src/hooks/lifecycle.js";
import { createSimulator } from "../src/simulator/index.js";
import type { TheAuth } from "../src/theauth.js";
import type { Permission } from "../src/types.js";
import { delegateTo, makeTheAuth, newAgent } from "./hook-test-utils.js";

const WILD: Permission[] = [{ resource: "mcp:github:*", actions: ["read"] }];

async function explainOf(
	theauth: TheAuth,
	agentId: string,
	action: string,
	resource: string,
	options?: ExplainOptions,
) {
	const r = await theauth.explain(agentId, action, resource, options);
	if (!r.success) throw new Error(r.error.message);
	return r.data;
}

async function auditCount(theauth: TheAuth): Promise<number> {
	return (await theauth.db.select().from(auditLogs)).length;
}

describe("explain parity with authorize", () => {
	const ip = "10.0.0.9";
	const scenarios: Array<{
		name: string;
		permissions: Permission[];
		action: string;
		resource: string;
		options?: ExplainOptions;
		delegated?: Permission[];
	}> = [
		{ name: "own allow", permissions: WILD, action: "read", resource: "mcp:github:repos" },
		{ name: "no permission", permissions: WILD, action: "write", resource: "mcp:github:repos" },
		{ name: "wrong resource", permissions: WILD, action: "read", resource: "mcp:slack:send" },
		{
			name: "ip not allowed",
			permissions: [
				{ resource: "tool:x", actions: ["run"], constraints: { ipAllowlist: ["1.2.3.4"] } },
			],
			action: "run",
			resource: "tool:x",
			options: { context: { ip } },
		},
		{
			name: "arg rejected",
			permissions: [
				{ resource: "tool:x", actions: ["run"], constraints: { allowedArgPatterns: ["^ok$"] } },
			],
			action: "run",
			resource: "tool:x",
			options: { arguments: { v: "bad" } },
		},
		{
			name: "approval required",
			permissions: [
				{ resource: "tool:x", actions: ["run"], constraints: { requireApproval: true } },
			],
			action: "run",
			resource: "tool:x",
		},
		{
			name: "delegated allow",
			permissions: [],
			delegated: WILD,
			action: "read",
			resource: "mcp:github:repos",
		},
		{
			name: "delegated ip deny",
			permissions: [],
			delegated: [
				{ resource: "mcp:github:*", actions: ["read"], constraints: { ipAllowlist: ["1.2.3.4"] } },
			],
			action: "read",
			resource: "mcp:github:repos",
			options: { context: { ip } },
		},
	];

	for (const s of scenarios) {
		it(s.name, async () => {
			const theauth = await makeTheAuth({});
			const agent = await newAgent(theauth, "bot", s.permissions);
			if (s.delegated) {
				const parent = await newAgent(theauth, "parent", [{ resource: "*", actions: ["*"] }]);
				await delegateTo(theauth, parent.id, agent.id, s.delegated);
			}
			const e = await explainOf(theauth, agent.id, s.action, s.resource, s.options);
			const a = await theauth.authorize(
				agent.id,
				{ action: s.action, resource: s.resource, arguments: s.options?.arguments },
				s.options?.context,
			);
			expect(e.allowed).toBe(a.allowed);
			expect(e.code).toBe(a.code);
		});
	}
});

describe("explain matched grant", () => {
	it("reports own rule index and match kinds", async () => {
		const theauth = await makeTheAuth({});
		const agent = await newAgent(theauth, "bot", [
			{ resource: "tool:exact", actions: ["run"] },
			{ resource: "mcp:github:*", actions: ["read"] },
			{ resource: "*", actions: ["*"] },
		]);
		const exact = await explainOf(theauth, agent.id, "run", "tool:exact");
		expect(exact.matchedGrant).toMatchObject({
			source: "own",
			index: 0,
			resourceMatch: "exact",
			actionMatch: "exact",
		});
		const prefix = await explainOf(theauth, agent.id, "read", "mcp:github:repos");
		expect(prefix.matchedGrant).toMatchObject({ index: 1, resourceMatch: "wildcard:prefix" });
		const all = await explainOf(theauth, agent.id, "anything", "other:thing");
		expect(all.matchedGrant).toMatchObject({
			index: 2,
			resourceMatch: "wildcard:all",
			actionMatch: "wildcard",
		});
		expect(all.attempts[0]?.source).toBe("own");
	});

	it("names the delegation link that carried the rule, root first", async () => {
		const theauth = await makeTheAuth({});
		const root = await newAgent(theauth, "root", [{ resource: "*", actions: ["*"] }]);
		const leaf = await newAgent(theauth, "leaf", []);
		const chain = await delegateTo(theauth, root.id, leaf.id, WILD);
		const e = await explainOf(theauth, leaf.id, "read", "mcp:github:repos");
		expect(e.allowed).toBe(true);
		expect(e.matchedGrant?.source).toBe("delegation");
		expect(e.matchedGrant?.link?.delegationId).toBe(chain.id);
		expect(e.delegation?.path).toEqual([root.id, leaf.id]);
		expect(e.attempts.map((x) => x.source)).toEqual(["own", "delegation"]);
	});

	it("denies on a delegated IP constraint and says why", async () => {
		const theauth = await makeTheAuth({});
		const root = await newAgent(theauth, "root", [{ resource: "*", actions: ["*"] }]);
		const leaf = await newAgent(theauth, "leaf", []);
		await delegateTo(theauth, root.id, leaf.id, [
			{ resource: "mcp:github:*", actions: ["read"], constraints: { ipAllowlist: ["1.2.3.4"] } },
		]);
		const e = await explainOf(theauth, leaf.id, "read", "mcp:github:repos", {
			context: { ip: "9.9.9.9" },
		});
		expect(e.allowed).toBe(false);
		expect(e.matchedGrant?.source).toBe("delegation");
		expect(e.constraints.at(-1)).toMatchObject({ constraint: "ipAllowlist", outcome: "fail" });
		expect(e.reason).toContain("delegated rule matched but failed");
		const ok = await explainOf(theauth, leaf.id, "read", "mcp:github:repos", {
			context: { ip: "1.2.3.4" },
		});
		expect(ok.allowed).toBe(true);
	});

	it("simulator keeps delegated constraints and agrees with explain", async () => {
		const theauth = await makeTheAuth({});
		const root = await newAgent(theauth, "root", [{ resource: "*", actions: ["*"] }]);
		const leaf = await newAgent(theauth, "leaf", []);
		await delegateTo(theauth, root.id, leaf.id, [
			{ resource: "mcp:github:*", actions: ["read"], constraints: { ipAllowlist: ["1.2.3.4"] } },
		]);
		const sim = createSimulator({ db: theauth.db });
		const r = await sim.simulate({
			agentId: leaf.id,
			action: "read",
			resource: "mcp:github:repos",
			context: { ip: "9.9.9.9" },
		});
		expect(r.success && r.data.allowed).toBe(false);
	});

	it("denies on a delegated rate limit that is spent", async () => {
		const theauth = await makeTheAuth({});
		const root = await newAgent(theauth, "root", [{ resource: "*", actions: ["*"] }]);
		const leaf = await newAgent(theauth, "leaf", []);
		await delegateTo(theauth, root.id, leaf.id, [
			{ resource: "mcp:github:*", actions: ["read"], constraints: { maxCallsPerHour: 1 } },
		]);
		const req = { action: "read", resource: "mcp:github:repos" };
		expect((await theauth.authorize(leaf.id, req)).allowed).toBe(true);
		const e = await explainOf(theauth, leaf.id, req.action, req.resource);
		expect(e.allowed).toBe(false);
		expect(e.code).toBe("no_permission");
		expect(e.constraints.at(-1)).toMatchObject({ constraint: "maxCallsPerHour", outcome: "fail" });
		expect((await theauth.authorize(leaf.id, req)).allowed).toBe(false);
	});
});

describe("explain has no side effects", () => {
	it("reports rate usage without incrementing it", async () => {
		const theauth = await makeTheAuth({});
		const agent = await newAgent(theauth, "bot", [
			{ resource: "tool:x", actions: ["run"], constraints: { maxCallsPerHour: 1 } },
		]);
		const first = await explainOf(theauth, agent.id, "run", "tool:x");
		await explainOf(theauth, agent.id, "run", "tool:x");
		expect(first.constraints[0]).toMatchObject({ constraint: "maxCallsPerHour", observed: 0 });
		expect((await theauth.db.select().from(rateLimits)).length).toBe(0);
		expect((await theauth.authorize(agent.id, { action: "run", resource: "tool:x" })).allowed).toBe(
			true,
		);
	});

	it("writes no audit rows and opens no approvals", async () => {
		const theauth = await makeTheAuth({});
		const agent = await newAgent(theauth, "bot", [
			{ resource: "tool:x", actions: ["run"], constraints: { requireApproval: true } },
		]);
		const before = await auditCount(theauth);
		const e = await explainOf(theauth, agent.id, "run", "tool:x");
		await explainOf(theauth, agent.id, "other", "tool:y");
		expect(e.decision).toBe("escalate");
		expect(e.code).toBe("approval_required");
		expect(await auditCount(theauth)).toBe(before);
		expect((await theauth.db.select().from(approvalRequests)).length).toBe(0);
	});
});

describe("explain hooks", () => {
	function hookSetup() {
		const calls: BeforeAuthorizeContext[] = [];
		const make = () =>
			makeTheAuth({
				hooks: {
					beforeAuthorize: async (ctx) => {
						calls.push(ctx);
						return { decision: "deny", reason: "nope", guard: "g1", ruleId: "r1" };
					},
				},
			});
		return { calls, make };
	}

	it("does not run the hook by default", async () => {
		const { calls, make } = hookSetup();
		const theauth = await make();
		const agent = await newAgent(theauth, "bot", WILD);
		const e = await explainOf(theauth, agent.id, "read", "mcp:github:repos");
		expect(calls).toHaveLength(0);
		expect(e.hook).toMatchObject({ configured: true, evaluated: false });
		expect(e.allowed).toBe(true);
	});

	it("runs the hook with dryRun and source explain when asked", async () => {
		const { calls, make } = hookSetup();
		const theauth = await make();
		const agent = await newAgent(theauth, "bot", WILD);
		const e = await explainOf(theauth, agent.id, "read", "mcp:github:repos", { runHooks: true });
		expect(calls).toHaveLength(1);
		expect(calls[0]).toMatchObject({ dryRun: true, source: "explain" });
		expect(e).toMatchObject({
			allowed: false,
			decision: "deny",
			code: "hook_denied",
			reason: "nope",
		});
		expect(e.hook).toMatchObject({
			evaluated: true,
			outcome: "deny",
			guard: "g1",
			ruleId: "r1",
		});
		expect(e.trace.some((t) => t.stage === "hook")).toBe(true);
	});

	it("reports unconfigured hooks", async () => {
		const theauth = await makeTheAuth({});
		const agent = await newAgent(theauth, "bot", WILD);
		const e = await explainOf(theauth, agent.id, "read", "mcp:github:repos", { runHooks: true });
		expect(e.hook).toEqual({ configured: false, evaluated: false });
	});
});

describe("explain edge cases", () => {
	it("explains an unknown agent as a deny", async () => {
		const theauth = await makeTheAuth({});
		const r = await theauth.explain("missing", "read", "x");
		expect(r.success).toBe(true);
		if (!r.success) return;
		expect(r.data).toMatchObject({
			decision: "deny",
			code: "agent_not_found",
			agent: null,
			delegation: null,
		});
	});

	it("rejects empty input", async () => {
		const theauth = await makeTheAuth({});
		const r = await theauth.explain("", "read", "x");
		expect(r).toMatchObject({ success: false, error: { code: "EXPLAIN_INVALID_INPUT" } });
	});

	it("explains a revoked agent", async () => {
		const theauth = await makeTheAuth({});
		const agent = await newAgent(theauth, "bot", WILD);
		await theauth.agent.revoke(agent.id);
		const e = await explainOf(theauth, agent.id, "read", "mcp:github:repos");
		expect(e).toMatchObject({ allowed: false, code: "agent_revoked" });
	});

	it("the at option flips a time window decision", async () => {
		const theauth = await makeTheAuth({});
		const agent = await newAgent(theauth, "bot", [
			{
				resource: "tool:x",
				actions: ["run"],
				constraints: { timeWindow: { start: "09:00", end: "17:00" } },
			},
		]);
		const noon = new Date(2026, 0, 5, 12, 0, 0);
		const night = new Date(2026, 0, 5, 3, 0, 0);
		const inside = await explainOf(theauth, agent.id, "run", "tool:x", { at: noon });
		const outside = await explainOf(theauth, agent.id, "run", "tool:x", { at: night });
		expect(inside.allowed).toBe(true);
		expect(outside).toMatchObject({ allowed: false, code: "time_restricted" });
		expect(outside.evaluatedAt).toEqual(night);
	});
});
