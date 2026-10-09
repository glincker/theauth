import { beforeEach, describe, expect, it } from "vitest";
import { auditLogs, rateLimits } from "../src/db/schema.js";
import { createSimulator } from "../src/simulator/index.js";
import type { Permission } from "../src/types.js";
import type { TheAuth } from "./helpers.js";
import { createTestTheAuth } from "./helpers.js";

const HOUR = 60 * 60 * 1000;

interface Fixture {
	name: string;
	permissions: Permission[];
	action: string;
	resource: string;
	args?: Record<string, unknown>;
	ip?: string;
	delegated?: Permission[];
}

const FIXTURES: Fixture[] = [
	{
		name: "exact match",
		permissions: [{ resource: "tool:file", actions: ["read"] }],
		action: "read",
		resource: "tool:file",
	},
	{
		name: "wrong action",
		permissions: [{ resource: "tool:file", actions: ["read"] }],
		action: "write",
		resource: "tool:file",
	},
	{
		name: "prefix wildcard",
		permissions: [{ resource: "mcp:github:*", actions: ["read"] }],
		action: "read",
		resource: "mcp:github:repos",
	},
	{
		name: "prefix wildcard miss",
		permissions: [{ resource: "mcp:github:*", actions: ["read"] }],
		action: "read",
		resource: "mcp:slack:send",
	},
	{
		name: "star resource and action",
		permissions: [{ resource: "*", actions: ["*"] }],
		action: "delete",
		resource: "anything:at:all",
	},
	{ name: "no permissions", permissions: [], action: "read", resource: "tool:file" },
	{
		name: "arg pattern pass",
		permissions: [
			{ resource: "tool:sh", actions: ["run"], constraints: { allowedArgPatterns: ["^[a-z]+$"] } },
		],
		action: "run",
		resource: "tool:sh",
		args: { cmd: "ls" },
	},
	{
		name: "arg pattern fail",
		permissions: [
			{ resource: "tool:sh", actions: ["run"], constraints: { allowedArgPatterns: ["^[a-z]+$"] } },
		],
		action: "run",
		resource: "tool:sh",
		args: { cmd: "rm -rf /" },
	},
	{
		name: "ip allowed",
		permissions: [
			{ resource: "tool:db", actions: ["read"], constraints: { ipAllowlist: ["10.0.0.0/8"] } },
		],
		action: "read",
		resource: "tool:db",
		ip: "10.1.2.3",
	},
	{
		name: "ip denied",
		permissions: [
			{ resource: "tool:db", actions: ["read"], constraints: { ipAllowlist: ["10.0.0.0/8"] } },
		],
		action: "read",
		resource: "tool:db",
		ip: "8.8.8.8",
	},
	{
		name: "ip missing",
		permissions: [
			{ resource: "tool:db", actions: ["read"], constraints: { ipAllowlist: ["10.0.0.0/8"] } },
		],
		action: "read",
		resource: "tool:db",
	},
	{
		name: "requires approval",
		permissions: [
			{ resource: "tool:pay", actions: ["send"], constraints: { requireApproval: true } },
		],
		action: "send",
		resource: "tool:pay",
	},
	{
		name: "approval on own, delegation grants",
		permissions: [
			{ resource: "tool:pay", actions: ["send"], constraints: { requireApproval: true } },
		],
		action: "send",
		resource: "tool:pay",
		delegated: [{ resource: "tool:pay", actions: ["send"] }],
	},
	{
		name: "delegation grants what own lacks",
		permissions: [],
		action: "read",
		resource: "mcp:github:repos",
		delegated: [{ resource: "mcp:github:*", actions: ["read"] }],
	},
	{
		name: "delegation does not cover",
		permissions: [],
		action: "write",
		resource: "mcp:github:repos",
		delegated: [{ resource: "mcp:github:*", actions: ["read"] }],
	},
];

describe("permission simulator", () => {
	let theauth: TheAuth;

	beforeEach(async () => {
		theauth = await createTestTheAuth({ auditAll: true });
	});

	async function makeAgent(permissions: Permission[], name = "sim-agent") {
		return theauth.agent.create({ ownerId: "user-1", name, type: "autonomous", permissions });
	}

	describe("parity with authorize", () => {
		for (const f of FIXTURES) {
			it(`agrees on: ${f.name}`, async () => {
				// A distinct owner permission set is needed for delegation fixtures.
				const agent = await makeAgent(f.permissions);
				if (f.delegated) {
					const parent = await makeAgent(f.delegated, "parent");
					await theauth.delegate({
						fromAgent: parent.id,
						toAgent: agent.id,
						permissions: f.delegated,
						expiresAt: new Date(Date.now() + HOUR),
					});
				}
				const sim = createSimulator({ db: theauth.db });
				const simulated = await sim.simulate({
					agentId: agent.id,
					action: f.action,
					resource: f.resource,
					context: { arguments: f.args, ip: f.ip },
				});
				const real = await theauth.authorize(agent.id, {
					action: f.action,
					resource: f.resource,
					arguments: f.args,
					ip: f.ip,
				});
				expect(simulated.success).toBe(true);
				if (!simulated.success) return;
				expect(simulated.data.allowed).toBe(real.allowed);
				if (!real.allowed && real.reason) {
					expect(simulated.data.reasons).toContain(real.reason);
				}
			});
		}

		it("agrees on rate limit exhaustion", async () => {
			const agent = await makeAgent([
				{ resource: "tool:api", actions: ["call"], constraints: { maxCallsPerHour: 2 } },
			]);
			const sim = createSimulator({ db: theauth.db });
			const req = { action: "call", resource: "tool:api" };
			for (let i = 0; i < 3; i++) {
				const before = await sim.simulate({ agentId: agent.id, ...req });
				const real = await theauth.authorize(agent.id, req);
				expect(before.success && before.data.allowed).toBe(real.allowed);
			}
		});
	});

	describe("no side effects", () => {
		it("writes no audit rows and leaves rate counters alone", async () => {
			const agent = await makeAgent([
				{ resource: "tool:api", actions: ["call"], constraints: { maxCallsPerHour: 5 } },
			]);
			const sim = createSimulator({ db: theauth.db });
			for (let i = 0; i < 10; i++) {
				const r = await sim.simulate({ agentId: agent.id, action: "call", resource: "tool:api" });
				expect(r.success && r.data.decision).toBe("allow");
			}
			expect(await theauth.db.select().from(auditLogs)).toHaveLength(0);
			expect(await theauth.db.select().from(rateLimits)).toHaveLength(0);
		});
	});

	describe("trace", () => {
		it("names the matching rule and wildcard kind", async () => {
			const agent = await makeAgent([{ resource: "mcp:github:*", actions: ["*"] }]);
			const sim = createSimulator({ db: theauth.db });
			const r = await sim.simulate({
				agentId: agent.id,
				action: "read",
				resource: "mcp:github:repos",
			});
			expect(r.success).toBe(true);
			if (!r.success) return;
			const step = r.data.trace.find((s) => s.stage === "permission");
			expect(step?.data).toMatchObject({
				rulePattern: "mcp:github:*",
				resourceMatch: "wildcard:prefix",
				actionMatch: "wildcard:all",
			});
		});

		it("reports observed values for ABAC conditions", async () => {
			const agent = await makeAgent([
				{ resource: "tool:db", actions: ["read"], constraints: { ipAllowlist: ["10.0.0.0/8"] } },
			]);
			const sim = createSimulator({ db: theauth.db });
			const r = await sim.simulate({
				agentId: agent.id,
				action: "read",
				resource: "tool:db",
				context: { ip: "9.9.9.9" },
			});
			expect(r.success && r.data.decision).toBe("deny");
			if (!r.success) return;
			const step = r.data.trace.find((s) => s.stage === "constraint");
			expect(step?.outcome).toBe("fail");
			expect(step?.data).toMatchObject({ constraint: "ipAllowlist", observed: "9.9.9.9" });
		});

		it("returns needs_approval for approval-gated rules", async () => {
			const agent = await makeAgent([
				{ resource: "tool:pay", actions: ["send"], constraints: { requireApproval: true } },
			]);
			const sim = createSimulator({ db: theauth.db });
			const r = await sim.simulate({ agentId: agent.id, action: "send", resource: "tool:pay" });
			expect(r.success && r.data.decision).toBe("needs_approval");
		});

		it("denies revoked agents and flags expiry", async () => {
			const agent = await makeAgent([{ resource: "*", actions: ["*"] }]);
			const sim = createSimulator({ db: theauth.db });
			const r = await sim.simulate({
				claims: { permissions: [{ resource: "*", actions: ["*"] }], status: "revoked" },
				action: "read",
				resource: "x",
			});
			expect(r.success && r.data.decision).toBe("deny");
			const stale = await sim.simulate({
				claims: {
					permissions: [{ resource: "*", actions: ["*"] }],
					expiresAt: new Date(Date.now() - HOUR),
				},
				action: "read",
				resource: "x",
			});
			expect(
				stale.success && stale.data.trace.some((s) => s.stage === "expiry" && s.outcome === "warn"),
			).toBe(true);
			expect(agent.id).toBeTruthy();
		});

		it("rejects input with neither agentId nor claims", async () => {
			const sim = createSimulator({ db: theauth.db });
			const r = await sim.simulate({ action: "read", resource: "x" });
			expect(r.success).toBe(false);
		});
	});

	describe("what-if overrides", () => {
		it("extra permissions flip a deny to allow", async () => {
			const agent = await makeAgent([]);
			const sim = createSimulator({ db: theauth.db });
			const base = { agentId: agent.id, action: "read", resource: "tool:file" };
			const denied = await sim.simulate(base);
			const allowed = await sim.simulate({
				...base,
				overrides: { extraPermissions: [{ resource: "tool:*", actions: ["read"] }] },
			});
			expect(denied.success && denied.data.decision).toBe("deny");
			expect(allowed.success && allowed.data.decision).toBe("allow");
		});

		it("supplied chains replace stored ones and honor depth limits", async () => {
			const agent = await makeAgent([]);
			const sim = createSimulator({ db: theauth.db });
			const chain = { permissions: [{ resource: "tool:*", actions: ["read"] }] };
			const ok = await sim.simulate({
				agentId: agent.id,
				action: "read",
				resource: "tool:file",
				overrides: { delegationChains: [{ ...chain, depth: 1, maxDepth: 2 }] },
			});
			const tooDeep = await sim.simulate({
				agentId: agent.id,
				action: "read",
				resource: "tool:file",
				overrides: { delegationChains: [{ ...chain, depth: 3, maxDepth: 2 }] },
			});
			expect(ok.success && ok.data.decision).toBe("allow");
			expect(tooDeep.success && tooDeep.data.decision).toBe("deny");
		});

		it("denies allowed actions that exceed the remaining budget", async () => {
			const agent = await makeAgent([{ resource: "*", actions: ["*"] }]);
			const sim = createSimulator({ db: theauth.db });
			const r = await sim.simulate({
				agentId: agent.id,
				action: "run",
				resource: "tool:llm",
				overrides: { budget: { limit: 10, spent: 9, cost: 2 } },
			});
			expect(r.success && r.data.decision).toBe("deny");
			if (!r.success) return;
			expect(r.data.trace.find((s) => s.stage === "budget")?.data).toMatchObject({
				remaining: 1,
				cost: 2,
			});
		});
	});

	describe("simulateMany and effectivePermissions", () => {
		it("builds an agent x action x resource matrix", async () => {
			const a = await makeAgent([{ resource: "tool:*", actions: ["read"] }], "a");
			const b = await makeAgent([], "b");
			const sim = createSimulator({ db: theauth.db });
			const r = await sim.simulateMany({
				agentIds: [a.id, b.id],
				actions: ["read", "write"],
				resources: ["tool:x"],
			});
			expect(r.success).toBe(true);
			if (!r.success) return;
			expect(r.data).toHaveLength(4);
			expect(r.data.filter((c) => c.decision === "allow")).toHaveLength(1);
		});

		it("refuses oversized matrices", async () => {
			const sim = createSimulator({ db: theauth.db });
			const many = Array.from({ length: 50 }, (_, i) => `v${i}`);
			const r = await sim.simulateMany({ agentIds: many, actions: many, resources: many });
			expect(r.success).toBe(false);
		});

		it("lists own and delegated rules", async () => {
			const parent = await makeAgent([{ resource: "mcp:github:*", actions: ["read"] }], "parent");
			const child = await makeAgent([{ resource: "tool:x", actions: ["run"] }], "child");
			await theauth.delegate({
				fromAgent: parent.id,
				toAgent: child.id,
				permissions: [{ resource: "mcp:github:*", actions: ["read"] }],
				expiresAt: new Date(Date.now() + HOUR),
			});
			const sim = createSimulator({ db: theauth.db });
			const r = await sim.effectivePermissions(child.id);
			expect(r.success).toBe(true);
			if (!r.success) return;
			expect(r.data.map((p) => p.source).sort()).toEqual(["delegation", "own"]);
			expect(r.data.every((p) => p.decision === "allow")).toBe(true);
		});
	});
});
