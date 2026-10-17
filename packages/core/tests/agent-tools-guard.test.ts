/** guardTool / guardTools: policy in front of an agent tool, tested against the real in-memory createTheAuth. No agent framework is involved. */

import { describe, expect, it, vi } from "vitest";
import { users } from "../src/db/schema.js";
import {
	guardTool,
	guardTools,
	ToolApprovalRequiredError,
	ToolDeniedError,
	ToolGuardError,
	ToolGuardFailedError,
} from "../src/index.js";
import type { TheAuth } from "../src/theauth.js";
import { createTheAuth } from "../src/theauth.js";

type PayArgs = { amount: number };

async function build(): Promise<TheAuth> {
	const auth = await createTheAuth({
		database: { provider: "sqlite", url: ":memory:" },
		agents: { enabled: true, maxPerUser: 10, defaultPermissions: [], auditAll: true },
		policy: {
			risk: { tiers: [{ tier: "large", when: { minAmount: 1000 }, require: "approval" }] },
		},
	});
	auth.db
		.insert(users)
		.values({
			id: "u1",
			email: "u1@t.test",
			name: "u1",
			createdAt: new Date(),
			updatedAt: new Date(),
		})
		.run();
	return auth;
}

async function agentWith(
	auth: TheAuth,
	name: string,
	resources: string[],
	requireApproval = false,
) {
	return auth.agent.create({
		ownerId: "u1",
		name,
		type: "autonomous",
		permissions: resources.map((resource) => ({
			resource,
			actions: ["execute"],
			constraints: requireApproval ? { requireApproval: true } : undefined,
		})),
	});
}

function payTool() {
	const execute = vi.fn(async (args: PayArgs) => ({ paid: args.amount }));
	return { execute, tool: { name: "pay", description: "Pay a vendor", execute } };
}

describe("guardTool", () => {
	it("runs an allowed tool and returns its result", async () => {
		const auth = await build();
		const agent = await agentWith(auth, "a1", ["tool:pay"]);
		const { tool, execute } = payTool();
		const guarded = guardTool(auth, { agentId: agent.id }, tool);
		await expect(guarded.execute({ amount: 5 })).resolves.toEqual({ paid: 5 });
		expect(execute).toHaveBeenCalledTimes(1);
	});

	it("denies an unpermitted tool without running execute", async () => {
		const auth = await build();
		const agent = await agentWith(auth, "a2", ["tool:other"]);
		const { tool, execute } = payTool();
		const guarded = guardTool(auth, { agentId: agent.id }, tool);
		const err = await guarded.execute({ amount: 5 }).catch((e: unknown) => e);
		expect(err).toBeInstanceOf(ToolDeniedError);
		expect(err).toBeInstanceOf(ToolGuardError);
		expect((err as ToolDeniedError).code).toBe("POLICY_NO_MATCHING_PERMISSION");
		expect((err as ToolDeniedError).message).toContain("denied");
		expect(execute).not.toHaveBeenCalled();
	});

	it("escalates a risk tier with an approval id and does not run execute", async () => {
		const auth = await build();
		const agent = await agentWith(auth, "a3", ["tool:pay"]);
		const { tool, execute } = payTool();
		const onEscalate = vi.fn();
		const guarded = guardTool(
			auth,
			{
				agentId: agent.id,
				risk: (a: PayArgs) => ({ amount: a.amount, currency: "USD" }),
				onEscalate,
			},
			tool,
		);
		await expect(guarded.execute({ amount: 5 })).resolves.toEqual({ paid: 5 });
		const err = await guarded.execute({ amount: 5000 }).catch((e: unknown) => e);
		expect(err).toBeInstanceOf(ToolApprovalRequiredError);
		const e = err as ToolApprovalRequiredError;
		expect(e.tier).toBe("large");
		expect(e.approvalRequestId).toBeTruthy();
		expect(e.message).toContain(String(e.approvalRequestId));
		expect(onEscalate).toHaveBeenCalledWith(
			expect.objectContaining({ tier: "large", approvalRequestId: e.approvalRequestId }),
		);
		expect(execute).toHaveBeenCalledTimes(1);
	});

	it("escalates a requireApproval permission", async () => {
		const auth = await build();
		const agent = await agentWith(auth, "a4", ["tool:pay"], true);
		const { tool, execute } = payTool();
		const guarded = guardTool(auth, { agentId: agent.id }, tool);
		await expect(guarded.execute({ amount: 1 })).rejects.toBeInstanceOf(ToolApprovalRequiredError);
		expect(execute).not.toHaveBeenCalled();
	});

	it("fails closed when policy evaluation throws", async () => {
		const { tool, execute } = payTool();
		const broken = {
			policy: {
				evaluate: async () => {
					throw new Error("db down");
				},
			},
		};
		const guarded = guardTool(broken, { agentId: "x" }, tool);
		const err = await guarded.execute({ amount: 1 }).catch((e: unknown) => e);
		expect(err).toBeInstanceOf(ToolGuardFailedError);
		expect((err as ToolGuardFailedError).reason).toBe("db down");
		expect(execute).not.toHaveBeenCalled();
	});

	it("fails closed when the agent id cannot be resolved", async () => {
		const auth = await build();
		const { tool, execute } = payTool();
		const guarded = guardTool(auth, { agentId: () => undefined }, tool);
		await expect(guarded.execute({ amount: 1 })).rejects.toBeInstanceOf(ToolGuardFailedError);
		expect(execute).not.toHaveBeenCalled();
	});

	it("keeps extra properties and the tool type", async () => {
		const auth = await build();
		const agent = await agentWith(auth, "a5", ["tool:pay"]);
		const { tool } = payTool();
		const rich = { ...tool, parameters: { type: "object" }, strict: true };
		const guarded = guardTool(auth, { agentId: agent.id }, rich);
		expect(guarded.description).toBe("Pay a vendor");
		expect(guarded.parameters).toEqual({ type: "object" });
		expect(guarded.strict).toBe(true);
		expect(guarded.name).toBe("pay");
		expect(guarded).not.toBe(rich);
		expect(guarded.execute).not.toBe(rich.execute);
	});

	it("derives the agent id from the call context", async () => {
		const auth = await build();
		const allowed = await agentWith(auth, "a6", ["tool:pay"]);
		const blocked = await agentWith(auth, "a7", []);
		type Ctx = { agent: string };
		const execute = vi.fn(async (args: PayArgs, _ctx?: Ctx) => args.amount);
		const guarded = guardTool(
			auth,
			{ agentId: (ctx: Ctx | undefined) => ctx?.agent },
			{ name: "pay", execute },
		);
		await expect(guarded.execute({ amount: 3 }, { agent: allowed.id })).resolves.toBe(3);
		await expect(guarded.execute({ amount: 3 }, { agent: blocked.id })).rejects.toBeInstanceOf(
			ToolDeniedError,
		);
		expect(execute).toHaveBeenCalledTimes(1);
	});

	it("reports every decision to onDecision and ignores its errors", async () => {
		const auth = await build();
		const agent = await agentWith(auth, "a8", ["tool:pay"]);
		const { tool } = payTool();
		const onDecision = vi.fn(() => {
			throw new Error("logger broke");
		});
		const guarded = guardTool(auth, { agentId: agent.id, onDecision }, tool);
		await expect(guarded.execute({ amount: 2 })).resolves.toEqual({ paid: 2 });
		expect(onDecision).toHaveBeenCalledWith(
			expect.objectContaining({ toolName: "pay", agentId: agent.id }),
		);
	});

	it("honors custom resource and action", async () => {
		const auth = await build();
		const agent = await agentWith(auth, "a9", ["billing:invoice"]);
		const { tool, execute } = payTool();
		const guarded = guardTool(auth, { agentId: agent.id, resource: "billing:invoice" }, tool);
		await expect(guarded.execute({ amount: 1 })).resolves.toEqual({ paid: 1 });
		const wrongAction = guardTool(
			auth,
			{ agentId: agent.id, resource: "billing:invoice", action: "delete" },
			tool,
		);
		await expect(wrongAction.execute({ amount: 1 })).rejects.toBeInstanceOf(ToolDeniedError);
		expect(execute).toHaveBeenCalledTimes(1);
	});
});

describe("guardTools", () => {
	it("guards a record using the keys as tool names", async () => {
		const auth = await build();
		const agent = await agentWith(auth, "b1", ["tool:pay"]);
		const run = vi.fn(async (_a: PayArgs) => "ok");
		const tools = guardTools(
			auth,
			{ agentId: agent.id },
			{ pay: { description: "p", execute: run }, wire: { description: "w", execute: run } },
		);
		await expect(tools.pay.execute({ amount: 1 })).resolves.toBe("ok");
		await expect(tools.wire.execute({ amount: 1 })).rejects.toBeInstanceOf(ToolDeniedError);
		expect(tools.pay.description).toBe("p");
		expect(run).toHaveBeenCalledTimes(1);
	});

	it("guards an array of named tools", async () => {
		const auth = await build();
		const agent = await agentWith(auth, "b2", ["tool:pay"]);
		const { tool } = payTool();
		const [pay, wire] = guardTools(auth, { agentId: agent.id }, [tool, { ...tool, name: "wire" }]);
		await expect(pay.execute({ amount: 1 })).resolves.toEqual({ paid: 1 });
		await expect(wire.execute({ amount: 1 })).rejects.toBeInstanceOf(ToolDeniedError);
	});
});

describe("guardTool with a human approval", () => {
	it("runs the approved call once, then refuses a replay", async () => {
		const auth = await build();
		const agent = await agentWith(auth, "a-approve", ["tool:pay"], true);
		const { tool, execute } = payTool();
		let approvalId: string | undefined;
		const guarded = guardTool(auth, { agentId: agent.id, approvalId: () => approvalId }, tool);

		const first = await guarded.execute({ amount: 7 }).catch((e: unknown) => e);
		expect(first).toBeInstanceOf(ToolApprovalRequiredError);
		const requestId = (first as ToolApprovalRequiredError).approvalRequestId;
		expect(requestId).toBeTruthy();
		expect(execute).not.toHaveBeenCalled();

		await auth.approval.approve(String(requestId), "human-1");
		approvalId = String(requestId);
		await expect(guarded.execute({ amount: 7 })).resolves.toEqual({ paid: 7 });
		expect(execute).toHaveBeenCalledTimes(1);

		const replay = await guarded.execute({ amount: 7 }).catch((e: unknown) => e);
		expect(replay).toBeInstanceOf(ToolDeniedError);
		expect((replay as ToolDeniedError).code).toBe("APPROVAL_ALREADY_USED");
		expect(execute).toHaveBeenCalledTimes(1);
	});

	it("refuses an approval that is still pending", async () => {
		const auth = await build();
		const agent = await agentWith(auth, "a-pending", ["tool:pay"], true);
		const { tool, execute } = payTool();
		let approvalId: string | undefined;
		const guarded = guardTool(auth, { agentId: agent.id, approvalId: () => approvalId }, tool);

		const first = await guarded.execute({ amount: 1 }).catch((e: unknown) => e);
		approvalId = String((first as ToolApprovalRequiredError).approvalRequestId);
		const second = await guarded.execute({ amount: 1 }).catch((e: unknown) => e);
		expect(second).toBeInstanceOf(ToolDeniedError);
		expect(execute).not.toHaveBeenCalled();
	});
});
