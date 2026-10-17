/** Guard paths the main guard tests do not reach: naming, resource and risk callbacks, escalation without details, hook failures and argument unwrapping. */

import { describe, expect, it, vi } from "vitest";
import {
	ToolApprovalRequiredError,
	ToolDeniedError,
	ToolGuardFailedError,
} from "../src/agent-tools/errors.js";
import type { GuardableTool, PolicyHost } from "../src/agent-tools/guard.js";
import { guardTool } from "../src/agent-tools/guard.js";
import type { EvaluateInput, EvaluateOptions, PolicyDecision } from "../src/policy/types.js";
import { tainted } from "../src/taint/labels.js";

interface Recorded {
	input: EvaluateInput;
	options: EvaluateOptions | undefined;
}

function decision(
	outcome: "allow" | "deny" | "escalate",
	extra: Partial<PolicyDecision> = {},
): PolicyDecision {
	const effect = outcome === "allow" ? "permit" : outcome === "deny" ? "deny" : "escalate";
	return {
		allowed: outcome === "allow",
		decision: outcome,
		effect,
		reason: "",
		cacheHit: false,
		durationMs: 0,
		...extra,
	};
}

/** A policy host that answers with a fixed decision or fails, and records every call. */
function hostWith(answer: () => Promise<PolicyDecision>): { host: PolicyHost; calls: Recorded[] } {
	const calls: Recorded[] = [];
	const host: PolicyHost = {
		policy: {
			evaluate: (input, options) => {
				calls.push({ input, options });
				return answer();
			},
		},
	};
	return { host, calls };
}

function allowing(): { host: PolicyHost; calls: Recorded[] } {
	return hostWith(async () => decision("allow"));
}

describe("guardTool naming", () => {
	it("refuses to wrap a nameless tool when no name option is given", () => {
		const { host } = allowing();
		const nameless: GuardableTool = { execute: async () => "ok" };
		expect(() => guardTool(host, { agentId: "a1" }, nameless)).toThrow(TypeError);
	});

	it("uses the name option for a nameless tool in the policy resource and in denials", async () => {
		const { host, calls } = hostWith(async () => decision("deny", { reason: "NOT_ALLOWED" }));
		const tool = guardTool(
			host,
			{ agentId: "a1", name: "lookup" },
			{
				execute: async () => "never",
			},
		);
		const err = await tool.execute({}).catch((e: unknown) => e);
		expect(err).toBeInstanceOf(ToolDeniedError);
		expect(err).toMatchObject({ toolName: "lookup", code: "NOT_ALLOWED" });
		expect(calls[0]?.input.resource).toBe("tool:lookup");
	});

	it("drops a free-text deny reason from the error code", async () => {
		const { host } = hostWith(async () => decision("deny", { reason: "Not allowed here, sorry" }));
		const tool = guardTool(host, { agentId: "a1", name: "lookup" }, { execute: async () => 1 });
		const err = await tool.execute({}).catch((e: unknown) => e);
		expect(err).toBeInstanceOf(ToolDeniedError);
		expect(err).toMatchObject({ code: "TOOL_DENIED" });
	});
});

describe("guardTool policy input", () => {
	it("derives the resource from the arguments when given a function", async () => {
		const { host, calls } = allowing();
		const tool = guardTool(
			host,
			{ agentId: "a1", name: "read", resource: (args: { id: string }) => `doc:${args.id}` },
			{ execute: async (args: { id: string }) => args.id },
		);
		expect(await tool.execute({ id: "42" })).toBe("42");
		expect(calls[0]?.input.resource).toBe("doc:42");
	});

	it("passes risk, approval id, action and the openApproval flag to the policy", async () => {
		const { host, calls } = allowing();
		const tool = guardTool(
			host,
			{
				agentId: "a1",
				name: "pay",
				action: "transfer",
				risk: (args: { amount: number }) => ({ amount: args.amount, currency: "EUR" }),
				approvalId: () => "req-7",
				openApproval: false,
			},
			{ execute: async () => "paid" },
		);
		expect(await tool.execute({ amount: 20 })).toBe("paid");
		const [call] = calls;
		expect(call?.input).toMatchObject({
			action: "transfer",
			approvalId: "req-7",
			context: { risk: { amount: 20, currency: "EUR" } },
		});
		expect(call?.options).toEqual({ openApproval: false });
	});

	it("merges an explicit provenance function with labels read from tainted arguments", async () => {
		const { host, calls } = allowing();
		const tool = guardTool(
			host,
			{
				agentId: "a1",
				name: "send",
				provenance: () => ({ url: ["untrusted_web"] }),
			},
			{ execute: async (args: { recipient: string; body: string }) => args },
		);
		const received = await tool.execute({
			recipient: tainted("ops@example.com", ["untrusted_web"]),
			body: "hi",
		});
		expect(received).toEqual({ recipient: "ops@example.com", body: "hi" });
		expect(calls[0]?.input.context?.provenance).toEqual({
			recipient: ["untrusted_web"],
			url: ["untrusted_web"],
		});
	});

	it("reports no agent id as a failed check without calling the policy", async () => {
		const { host, calls } = allowing();
		const tool = guardTool(
			host,
			{ agentId: () => undefined, name: "lookup" },
			{ execute: async () => 1 },
		);
		const err = await tool.execute({}).catch((e: unknown) => e);
		expect(err).toBeInstanceOf(ToolGuardFailedError);
		expect(err).toMatchObject({ toolName: "lookup", agentId: undefined });
		expect(calls).toHaveLength(0);
	});

	it("fails closed with an unknown reason when the policy rejects with a non-Error", async () => {
		const { host } = hostWith(() => Promise.reject("policy store offline"));
		const tool = guardTool(host, { agentId: "a1", name: "lookup" }, { execute: async () => 1 });
		const err = await tool.execute({}).catch((e: unknown) => e);
		expect(err).toBeInstanceOf(ToolGuardFailedError);
		expect(err).toMatchObject({ reason: "unknown error", agentId: "a1" });
	});
});

describe("guardTool argument unwrapping", () => {
	it("hands a tainted first argument to the tool as its plain value", async () => {
		const { host } = allowing();
		const tool = guardTool(
			host,
			{ agentId: "a1", name: "echo" },
			{
				execute: async (value: string) => value.toUpperCase(),
			},
		);
		expect(await tool.execute(tainted("ops", ["untrusted_web"]))).toBe("OPS");
	});

	it("passes primitive, null and array first arguments through unchanged", async () => {
		const { host } = allowing();
		const seen: unknown[] = [];
		const tool = guardTool(
			host,
			{ agentId: "a1", name: "any" },
			{
				execute: async (value: unknown) => {
					seen.push(value);
					return value;
				},
			},
		);
		await tool.execute("text");
		await tool.execute(null);
		await tool.execute([1, 2]);
		expect(seen).toEqual(["text", null, [1, 2]]);
	});
});

describe("guardTool escalation and hooks", () => {
	it("falls back to an unknown tier and approval when the escalation has no details", async () => {
		const seen: string[] = [];
		const { host } = hostWith(async () => decision("escalate", { reason: "needs a human" }));
		const tool = guardTool(
			host,
			{
				agentId: "a1",
				name: "wire",
				onEscalate: (info) => {
					seen.push(`${info.tier}/${info.requirement}`);
				},
			},
			{ execute: async () => "sent" },
		);
		const err = await tool.execute({}).catch((e: unknown) => e);
		expect(err).toBeInstanceOf(ToolApprovalRequiredError);
		expect(err).toMatchObject({ tier: "unknown", requirement: "approval" });
		expect(seen).toEqual(["unknown/approval"]);
	});

	it("passes the escalation tier, requirement and request id through to the error", async () => {
		const { host } = hostWith(async () =>
			decision("escalate", {
				reason: "step up",
				escalation: {
					tier: "high",
					requirement: "step_up",
					reason: "step up",
					approvalRequestId: "apr-1",
				},
			}),
		);
		const tool = guardTool(host, { agentId: "a1", name: "wire" }, { execute: async () => 1 });
		const err = await tool.execute({}).catch((e: unknown) => e);
		expect(err).toMatchObject({
			tier: "high",
			requirement: "step_up",
			approvalRequestId: "apr-1",
		});
	});

	it("still runs an allowed tool when the decision logger throws", async () => {
		const { host } = allowing();
		const execute = vi.fn(async () => "done");
		const tool = guardTool(
			host,
			{
				agentId: "a1",
				name: "lookup",
				onDecision: () => {
					throw new Error("log sink down");
				},
			},
			{ execute },
		);
		expect(await tool.execute({})).toBe("done");
		expect(execute).toHaveBeenCalledTimes(1);
	});

	it("does not run the tool when the escalation hook throws", async () => {
		const { host } = hostWith(async () => decision("escalate", { reason: "x" }));
		const execute = vi.fn(async () => "never");
		const tool = guardTool(
			host,
			{
				agentId: "a1",
				name: "wire",
				onEscalate: () => {
					throw new Error("notifier down");
				},
			},
			{ execute },
		);
		await expect(tool.execute({})).rejects.toThrow("notifier down");
		expect(execute).not.toHaveBeenCalled();
	});
});
