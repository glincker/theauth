/** Delegated agents under policy.evaluate: shared permission merge, constraints and root human carried through the chain, owner match, escalate auditing. */

import { eq } from "drizzle-orm";
import { beforeEach, describe, expect, it } from "vitest";
import { auditLogs, users } from "../src/db/schema.js";
import { makeDecision, outcomeOf } from "../src/policy/decision.js";
import type { TheAuth } from "../src/theauth.js";
import { createTheAuth } from "../src/theauth.js";

const PAY = "tool:pay";
const settle = () => new Promise((r) => setTimeout(r, 30));

async function build() {
	const auth = await createTheAuth({
		database: { provider: "sqlite", url: ":memory:" },
		agents: { enabled: true, maxPerUser: 10, defaultPermissions: [], auditAll: true },
		policy: {
			policyVersion: "v-test-1",
			risk: { tiers: [{ tier: "large", when: { minAmount: 1000 }, require: "approval" }] },
		},
	});
	for (const id of ["user-1", "user-2"]) {
		auth.db
			.insert(users)
			.values({ id, email: `${id}@t.test`, name: id, createdAt: new Date(), updatedAt: new Date() })
			.run();
	}
	return auth;
}

async function agent(auth: TheAuth, ownerId: string, name: string, perms = true) {
	return auth.agent.create({
		ownerId,
		name,
		type: "autonomous",
		permissions: perms ? [{ resource: PAY, actions: ["execute"], constraints: undefined }] : [],
	});
}

const soon = () => new Date(Date.now() + 60_000);

describe("PolicyDecision field coherence", () => {
	it("derives decision and allowed from effect", () => {
		const base = { reason: "r", cacheHit: false, durationMs: 0 };
		expect(makeDecision({ ...base, effect: "permit" })).toMatchObject({
			decision: "allow",
			allowed: true,
		});
		expect(makeDecision({ ...base, effect: "indeterminate" })).toMatchObject({
			decision: "deny",
			allowed: false,
		});
		expect(makeDecision({ ...base, effect: "escalate" })).toMatchObject({
			decision: "escalate",
			allowed: false,
		});
		// A contradictory hand-built input is corrected, effect stays the source of truth.
		expect(
			makeDecision({ ...base, effect: "deny", decision: "allow", allowed: true }),
		).toMatchObject({
			decision: "deny",
			allowed: false,
		});
		expect(outcomeOf("permit")).toBe("allow");
	});
});

describe("delegated agents in policy.evaluate", () => {
	let auth: TheAuth;
	beforeEach(async () => {
		auth = await build();
	});

	it("applies a risk tier to a delegated agent", async () => {
		const parent = await agent(auth, "user-1", "parent");
		const child = await agent(auth, "user-1", "child", false);
		await auth.delegate({
			fromAgent: parent.id,
			toAgent: child.id,
			permissions: [{ resource: PAY, actions: ["execute"] }],
			expiresAt: soon(),
		});
		const small = await auth.policy.evaluate({
			subject: { agentId: child.id },
			action: "execute",
			resource: PAY,
			context: { risk: { amount: 5 } },
		});
		expect(small.decision).toBe("allow");
		const big = await auth.policy.evaluate({
			subject: { agentId: child.id },
			action: "execute",
			resource: PAY,
			context: { risk: { amount: 5000 } },
		});
		expect(big.decision).toBe("escalate");
		expect(big.allowed).toBe(false);
	});

	it("carries requireApproval from the grant and the parent, narrowing only", async () => {
		const parent = await auth.agent.create({
			ownerId: "user-1",
			name: "parent",
			type: "autonomous",
			permissions: [
				{
					resource: PAY,
					actions: ["execute"],
					constraints: { requireApproval: true, maxCallsPerHour: 5 },
				},
			],
		});
		const child = await agent(auth, "user-1", "child", false);
		// The child asks for a looser limit and no approval flag: it still inherits both.
		const chain = await auth.delegate({
			fromAgent: parent.id,
			toAgent: child.id,
			permissions: [{ resource: PAY, actions: ["execute"], constraints: { maxCallsPerHour: 50 } }],
			expiresAt: soon(),
		});
		expect(chain.permissions[0]?.constraints).toEqual({
			requireApproval: true,
			maxCallsPerHour: 5,
		});
		const d = await auth.policy.evaluate({
			subject: { agentId: child.id },
			action: "execute",
			resource: PAY,
		});
		expect(d.decision).toBe("escalate");
		expect(d.effect).toBe("escalate");
	});

	it("a grant-level requireApproval escalates a delegated agent", async () => {
		const parent = await agent(auth, "user-1", "parent");
		const child = await agent(auth, "user-1", "child", false);
		await auth.delegate({
			fromAgent: parent.id,
			toAgent: child.id,
			permissions: [
				{ resource: PAY, actions: ["execute"], constraints: { requireApproval: true } },
			],
			expiresAt: soon(),
		});
		const d = await auth.policy.evaluate({
			subject: { agentId: child.id },
			action: "execute",
			resource: PAY,
		});
		expect(d.decision).toBe("escalate");
	});
});

describe("root human through the delegation chain", () => {
	it("records every hop and the original owner", async () => {
		const auth = await build();
		const a = await agent(auth, "user-1", "A");
		const b = await agent(auth, "user-2", "B", false);
		const c = await agent(auth, "user-2", "C", false);
		await auth.delegate({
			fromAgent: a.id,
			toAgent: b.id,
			permissions: [{ resource: PAY, actions: ["execute"] }],
			expiresAt: soon(),
		});
		const hop2 = await auth.delegate({
			fromAgent: b.id,
			toAgent: c.id,
			permissions: [{ resource: PAY, actions: ["execute"] }],
			expiresAt: soon(),
		});
		expect(hop2.rootOwnerId).toBe("user-1");
		expect(hop2.path).toEqual([a.id, b.id, c.id]);

		const d = await auth.policy.evaluate({
			subject: { agentId: c.id },
			action: "execute",
			resource: PAY,
		});
		expect(d.principal).toEqual({
			actorId: c.id,
			subjectId: "user-1",
			delegationChain: [a.id, b.id, c.id],
		});
		await settle();
		const rows = await auth.db
			.select()
			.from(auditLogs)
			.where(eq(auditLogs.id, d.auditId ?? ""));
		expect(rows[0]).toMatchObject({
			subjectId: "user-1",
			actorId: c.id,
			delegationChain: [a.id, b.id, c.id],
			policyVersion: "v-test-1",
		});
	});
});

describe("owner match", () => {
	it("denies when the named owner is not the agent's owner", async () => {
		const auth = await build();
		const a = await agent(auth, "user-1", "A");
		const ok = await auth.policy.evaluate({
			subject: { agentId: a.id, ownerId: "user-1" },
			action: "execute",
			resource: PAY,
		});
		expect(ok.decision).toBe("allow");
		const bad = await auth.policy.evaluate({
			subject: { agentId: a.id, ownerId: "user-2" },
			action: "execute",
			resource: PAY,
		});
		expect(bad.decision).toBe("deny");
		expect(bad.reason).toBe("POLICY_OWNER_MISMATCH");
	});
});

describe("agent status", () => {
	it("denies a revoked agent even when a decision is cached", async () => {
		const auth = await build();
		const a = await agent(auth, "user-1", "A");
		const req = { subject: { agentId: a.id }, action: "execute", resource: PAY };
		expect((await auth.policy.evaluate(req)).decision).toBe("allow");
		await auth.agent.revoke(a.id);
		const after = await auth.policy.evaluate(req);
		expect(after.decision).toBe("deny");
		expect(after.reason).toBe("POLICY_AGENT_INACTIVE");
	});
});

describe("escalate audit outcome", () => {
	it("records an escalated row with the policy version", async () => {
		const auth = await build();
		const a = await agent(auth, "user-1", "A");
		const d = await auth.policy.evaluate({
			subject: { agentId: a.id },
			action: "execute",
			resource: PAY,
			context: { risk: { amount: 9000 } },
		});
		expect(d.decision).toBe("escalate");
		await settle();
		const rows = await auth.db
			.select()
			.from(auditLogs)
			.where(eq(auditLogs.id, d.auditId ?? ""));
		expect(rows).toHaveLength(1);
		expect(rows[0]?.result).toBe("escalated");
		expect(rows[0]?.reason).toBeTruthy();
		expect(rows[0]?.policyVersion).toBe("v-test-1");
	});
});
