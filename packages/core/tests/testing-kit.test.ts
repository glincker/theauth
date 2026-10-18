import { describe, expect, it } from "vitest";
import {
	createTestAuth,
	definePolicySuite,
	expectAllowed,
	expectDenied,
	formatPolicyReport,
	runPolicySuite,
	theauthMatchers,
} from "../src/testing/index.js";

const suite = definePolicySuite({
	agents: {
		root: { permissions: [{ resource: "mcp:github:*", actions: ["read", "write"] }] },
		reader: {
			permissions: [],
			delegatedFrom: {
				agent: "root",
				permissions: [{ resource: "mcp:github:*", actions: ["read"] }],
			},
		},
	},
	cases: [
		{
			name: "root writes",
			agent: "root",
			action: "write",
			resource: "mcp:github:repos",
			expect: "allow",
		},
		{
			name: "reader reads",
			agent: "reader",
			action: "read",
			resource: "mcp:github:repos",
			expect: "allow",
		},
		{
			name: "reader cannot write",
			agent: "reader",
			action: "write",
			resource: "mcp:github:repos",
			expect: "deny",
			code: "no_permission",
		},
	],
});

describe("testing kit", () => {
	it("passes a suite", async () => {
		const auth = await createTestAuth();
		const report = await runPolicySuite(auth, suite);
		expect(report).toEqual({ passed: 3, failed: [] });
	});

	it("reports failures with explain output", async () => {
		const auth = await createTestAuth();
		const bad = definePolicySuite({
			agents: suite.agents,
			cases: [
				{
					name: "wrongly allowed",
					agent: "reader",
					action: "write",
					resource: "mcp:github:repos",
					expect: "allow",
				},
			],
		});
		const report = await runPolicySuite(auth, bad);
		expect(report.passed).toBe(0);
		expect(report.failed[0]?.got.code).toBe("no_permission");
		const text = formatPolicyReport(report);
		expect(text).toContain("FAIL wrongly allowed");
		expect(text).toContain("near miss");
	});

	it("seeds agents and asserts with expectAllowed and expectDenied", async () => {
		const auth = await createTestAuth();
		const agent = await auth.seedAgent({ permissions: [{ resource: "tool:x", actions: ["run"] }] });
		await expectAllowed(auth, { agentId: agent.id, action: "run", resource: "tool:x" });
		await expectDenied(
			auth,
			{ agentId: agent.id, action: "run", resource: "tool:y" },
			"no_permission",
		);
		await expect(
			expectAllowed(auth, { agentId: agent.id, action: "run", resource: "tool:y" }),
		).rejects.toThrow(/no_permission/);
		await expect(
			expectDenied(auth, { agentId: agent.id, action: "run", resource: "tool:x" }),
		).rejects.toThrow(/expected a denial/);
	});

	it("matchers explain themselves", () => {
		const deny = {
			allowed: false,
			code: "rate_limited" as const,
			reason: "slow down",
			auditId: "a",
		};
		expect(theauthMatchers.toBeAllowed(deny).pass).toBe(false);
		expect(theauthMatchers.toBeAllowed(deny).message()).toContain("slow down");
		expect(theauthMatchers.toBeDeniedWith(deny, "rate_limited").pass).toBe(true);
		expect(theauthMatchers.toBeDeniedWith(deny, "no_permission").message()).toContain(
			"rate_limited",
		);
	});
});
