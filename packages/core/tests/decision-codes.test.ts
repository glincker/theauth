/** Typed decision codes: carried on authorize() results, onViolation and PolicyDecision, never parsed from reason text. */
import { eq } from "drizzle-orm";
import { describe, expect, it } from "vitest";
import { agents } from "../src/db/schema.js";
import { classifyViolation } from "../src/hooks/index.js";
import type { TheAuthHooks } from "../src/hooks/lifecycle.js";
import type { DecisionCode } from "../src/permission/index.js";
import { DECISION_CODES, isDecisionCode, violationTypeOf } from "../src/permission/index.js";
import type { TheAuth } from "../src/theauth.js";
import { createTheAuth } from "../src/theauth.js";
import type { Permission } from "../src/types.js";

interface Violation {
	type: string;
	code: DecisionCode;
	reason: string;
}

async function setup(extra?: {
	policy?: Parameters<typeof createTheAuth>[0]["policy"];
}): Promise<{ theauth: TheAuth; violations: Violation[] }> {
	const violations: Violation[] = [];
	const hooks: TheAuthHooks = {
		onViolation: async (v) => {
			violations.push({ type: v.type, code: v.code, reason: v.reason });
		},
	};
	const theauth = await createTheAuth({
		database: { provider: "sqlite", url: ":memory:" },
		agents: {
			enabled: true,
			maxPerUser: 20,
			defaultPermissions: [],
			auditAll: true,
			tokenExpiry: "24h",
		},
		hooks,
		policy: extra?.policy,
	});
	const now = new Date();
	await theauth.db
		.insert((await import("../src/db/schema.js")).users)
		.values({ id: "user-1", email: "t@example.com", name: "T", createdAt: now, updatedAt: now })
		.run();
	return { theauth, violations };
}

async function makeAgent(theauth: TheAuth, permissions: Permission[], name = "bot") {
	return theauth.agent.create({ ownerId: "user-1", name, type: "autonomous", permissions });
}

const flush = () => new Promise((resolve) => setTimeout(resolve, 10));

describe("DECISION_CODES helpers", () => {
	it("isDecisionCode accepts every code and rejects other values", () => {
		for (const code of Object.values(DECISION_CODES)) expect(isDecisionCode(code)).toBe(true);
		expect(isDecisionCode("nope")).toBe(false);
		expect(isDecisionCode(undefined)).toBe(false);
	});

	it("violationTypeOf groups codes", () => {
		expect(violationTypeOf("rate_limited")).toBe("rate_limited");
		expect(violationTypeOf("ip_not_allowed")).toBe("ip_blocked");
		expect(violationTypeOf("time_restricted")).toBe("time_restricted");
		expect(violationTypeOf("approval_required")).toBe("approval_required");
		expect(violationTypeOf("approval_invalid")).toBe("approval_required");
		expect(violationTypeOf("no_permission")).toBe("permission_denied");
		expect(violationTypeOf("agent_revoked")).toBe("permission_denied");
		expect(violationTypeOf("hook_denied")).toBe("permission_denied");
	});
});

describe("authorize() codes", () => {
	const farPast = "00:00";
	const rows: Array<{
		name: string;
		permission: Permission;
		request: { arguments?: Record<string, unknown>; ip?: string; approvalId?: string };
		code: DecisionCode;
		type: string;
		repeat?: number;
	}> = [
		{
			name: "no permission",
			permission: { resource: "mcp:other", actions: ["read"] },
			request: {},
			code: "no_permission",
			type: "permission_denied",
		},
		{
			name: "rate limit hit",
			permission: { resource: "mcp:x", actions: ["read"], constraints: { maxCallsPerHour: 1 } },
			request: {},
			code: "rate_limited",
			type: "rate_limited",
			repeat: 2,
		},
		{
			name: "IP missing",
			permission: {
				resource: "mcp:x",
				actions: ["read"],
				constraints: { ipAllowlist: ["10.0.0.1"] },
			},
			request: {},
			code: "ip_not_allowed",
			type: "ip_blocked",
		},
		{
			name: "IP not in list",
			permission: {
				resource: "mcp:x",
				actions: ["read"],
				constraints: { ipAllowlist: ["10.0.0.1"] },
			},
			request: { ip: "10.0.0.2" },
			code: "ip_not_allowed",
			type: "ip_blocked",
		},
		{
			name: "outside time window",
			permission: {
				resource: "mcp:x",
				actions: ["read"],
				constraints: { timeWindow: { start: farPast, end: farPast } },
			},
			request: {},
			code: "time_restricted",
			type: "time_restricted",
		},
		{
			name: "argument pattern mismatch",
			permission: {
				resource: "mcp:x",
				actions: ["read"],
				constraints: { allowedArgPatterns: ["^safe$"] },
			},
			request: { arguments: { q: "unsafe" } },
			code: "argument_rejected",
			type: "permission_denied",
		},
		{
			name: "invalid regex",
			permission: {
				resource: "mcp:x",
				actions: ["read"],
				constraints: { allowedArgPatterns: ["("] },
			},
			request: { arguments: { q: "a" } },
			code: "argument_rejected",
			type: "permission_denied",
		},
		{
			name: "approval required without id",
			permission: { resource: "mcp:x", actions: ["read"], constraints: { requireApproval: true } },
			request: {},
			code: "approval_required",
			type: "approval_required",
		},
		{
			name: "bad approval id",
			permission: { resource: "mcp:x", actions: ["read"], constraints: { requireApproval: true } },
			request: { approvalId: "apr_missing" },
			code: "approval_invalid",
			type: "approval_required",
		},
	];

	for (const row of rows) {
		it(`${row.name} -> ${row.code}`, async () => {
			const { theauth, violations } = await setup();
			const agent = await makeAgent(theauth, [row.permission]);
			let result = await theauth.authorize(agent.id, {
				action: "read",
				resource: "mcp:x",
				...row.request,
			});
			for (let i = 1; i < (row.repeat ?? 1); i++) {
				result = await theauth.authorize(agent.id, {
					action: "read",
					resource: "mcp:x",
					...row.request,
				});
			}
			expect(result.allowed).toBe(false);
			expect(result.code).toBe(row.code);
			expect(violationTypeOf(result.code as DecisionCode)).toBe(row.type);
			await flush();
			const last = violations.at(-1);
			expect(last?.code).toBe(row.code);
			expect(last?.type).toBe(row.type);
		});
	}

	it("allowed result carries code allowed", async () => {
		const { theauth } = await setup();
		const agent = await makeAgent(theauth, [{ resource: "mcp:x", actions: ["read"] }]);
		const result = await theauth.authorize(agent.id, { action: "read", resource: "mcp:x" });
		expect(result.code).toBe("allowed");
	});

	it("consumed approval carries code approval_consumed", async () => {
		const { theauth } = await setup();
		const agent = await makeAgent(theauth, [
			{ resource: "mcp:x", actions: ["read"], constraints: { requireApproval: true } },
		]);
		const req = await theauth.approval.request({
			agentId: agent.id,
			userId: "user-1",
			action: "read",
			resource: "mcp:x",
		});
		await theauth.approval.approve(req.id, "human-1");
		const result = await theauth.authorize(agent.id, {
			action: "read",
			resource: "mcp:x",
			approvalId: req.id,
		});
		expect(result.allowed).toBe(true);
		expect(result.code).toBe("approval_consumed");
	});

	it("unknown agent -> agent_not_found", async () => {
		const { theauth } = await setup();
		const result = await theauth.authorize("missing", { action: "read", resource: "mcp:x" });
		expect(result.code).toBe("agent_not_found");
	});

	it("revoked agent -> agent_revoked", async () => {
		const { theauth } = await setup();
		const agent = await makeAgent(theauth, [{ resource: "mcp:x", actions: ["read"] }]);
		await theauth.agent.revoke(agent.id);
		const result = await theauth.authorize(agent.id, { action: "read", resource: "mcp:x" });
		expect(result.code).toBe("agent_revoked");
	});

	it("expired agent -> agent_expired", async () => {
		const { theauth } = await setup();
		const agent = await makeAgent(theauth, [{ resource: "mcp:x", actions: ["read"] }]);
		await theauth.db.update(agents).set({ status: "expired" }).where(eq(agents.id, agent.id));
		const result = await theauth.authorize(agent.id, { action: "read", resource: "mcp:x" });
		expect(result.code).toBe("agent_expired");
	});

	it("invalid token -> invalid_token", async () => {
		const { theauth } = await setup();
		const result = await theauth.authorizeByToken("not-a-token", {
			action: "read",
			resource: "mcp:x",
		});
		expect(result.code).toBe("invalid_token");
	});

	it("authorizeByToken carries permission codes", async () => {
		const { theauth } = await setup();
		const agent = await makeAgent(theauth, [{ resource: "mcp:x", actions: ["read"] }]);
		const ok = await theauth.authorizeByToken(agent.token, { action: "read", resource: "mcp:x" });
		const denied = await theauth.authorizeByToken(agent.token, {
			action: "write",
			resource: "mcp:x",
		});
		expect(ok.code).toBe("allowed");
		expect(denied.code).toBe("no_permission");
	});

	it("beforeAuthorize block -> hook_denied", async () => {
		const violations: Violation[] = [];
		const theauth = await createTheAuth({
			database: { provider: "sqlite", url: ":memory:" },
			agents: {
				enabled: true,
				maxPerUser: 5,
				defaultPermissions: [],
				auditAll: true,
				tokenExpiry: "24h",
			},
			hooks: {
				beforeAuthorize: async () => ({ allow: false, reason: "rate of change too high" }),
				onViolation: async (v) => {
					violations.push({ type: v.type, code: v.code, reason: v.reason });
				},
			},
		});
		await theauth.user.create({ id: "user-1", email: "t@example.com" });
		const agent = await makeAgent(theauth, [{ resource: "mcp:x", actions: ["read"] }]);
		const result = await theauth.authorize(agent.id, { action: "read", resource: "mcp:x" });
		expect(result.code).toBe("hook_denied");
		expect(violations[0]).toMatchObject({ code: "hook_denied", type: "permission_denied" });
	});

	it("regression: an agent named pirate-bot denied for no permission is permission_denied", async () => {
		const { theauth, violations } = await setup();
		const agent = await makeAgent(theauth, [], "pirate-bot");
		const result = await theauth.authorize(agent.id, { action: "read", resource: "mcp:x" });
		expect(result.reason).toContain("pirate-bot");
		expect(result.code).toBe("no_permission");
		await flush();
		expect(violations.at(-1)?.type).toBe("permission_denied");
	});

	it("delegated fallback still prefers the approval failure, decided by code", async () => {
		const { theauth } = await setup();
		const parent = await makeAgent(
			theauth,
			[{ resource: "mcp:x", actions: ["read"], constraints: { requireApproval: true } }],
			"parent",
		);
		const child = await makeAgent(theauth, [{ resource: "mcp:other", actions: ["read"] }], "child");
		await theauth.delegate({
			fromAgent: parent.id,
			toAgent: child.id,
			permissions: [
				{ resource: "mcp:x", actions: ["read"], constraints: { requireApproval: true } },
			],
			expiresAt: new Date(Date.now() + 3_600_000),
		});
		const result = await theauth.authorize(child.id, { action: "read", resource: "mcp:x" });
		expect(result.allowed).toBe(false);
		expect(result.code).toBe("approval_required");
	});
});

describe("classifyViolation (deprecated)", () => {
	it("is still exported and keeps the old contract", () => {
		expect(classifyViolation("rate limit exceeded")).toBe("rate_limited");
		expect(classifyViolation("IP_NOT_ALLOWED")).toBe("ip_blocked");
		expect(classifyViolation("outside time window")).toBe("time_restricted");
		expect(classifyViolation("needs approval")).toBe("approval_required");
		expect(classifyViolation(undefined)).toBe("permission_denied");
	});
});

describe("policy.evaluate codes", () => {
	it("returns codes for permit, owner mismatch, inactive agent, taint and risk", async () => {
		const { theauth } = await setup({
			policy: {
				risk: { tiers: [{ tier: "high", when: { minAmount: 100 }, require: "approval" }] },
				taint: {
					rules: [
						{
							id: "untrusted",
							resource: "tool:*",
							args: { to: { forbid: ["untrusted_*"] } },
							tier: "taint",
							effect: "deny",
						},
					],
				},
			},
		});
		const agent = await makeAgent(theauth, [{ resource: "tool:pay", actions: ["execute"] }]);
		const base = { action: "execute", resource: "tool:pay" };

		const permit = await theauth.policy.evaluate({ subject: { agentId: agent.id }, ...base });
		expect(permit.code).toBe("allowed");

		const mismatch = await theauth.policy.evaluate({
			subject: { agentId: agent.id, ownerId: "someone-else" },
			...base,
		});
		expect(mismatch.code).toBe("owner_mismatch");

		const missing = await theauth.policy.evaluate({ subject: { agentId: "nope" }, ...base });
		expect(missing.code).toBe("agent_not_found");

		const risk = await theauth.policy.evaluate({
			subject: { agentId: agent.id },
			...base,
			context: { risk: { amount: 500 } },
		});
		expect(risk.code).toBe("risk_escalation");

		const taint = await theauth.policy.evaluate({
			subject: { agentId: agent.id },
			...base,
			context: { provenance: { to: ["untrusted_web"] } },
		});
		expect(taint.code).toBe("taint_violation");

		await theauth.agent.revoke(agent.id);
		const inactive = await theauth.policy.evaluate({ subject: { agentId: agent.id }, ...base });
		expect(inactive.code).toBe("agent_revoked");
	});

	it("no matching permission carries no_permission", async () => {
		const { theauth } = await setup();
		const agent = await makeAgent(theauth, []);
		const d = await theauth.policy.evaluate({
			subject: { agentId: agent.id },
			action: "execute",
			resource: "tool:pay",
		});
		expect(d.allowed).toBe(false);
		expect(d.code).toBe("no_permission");
	});
});
