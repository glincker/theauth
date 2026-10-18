import type { PolicyHost } from "@glinr/theauth";
import { ToolApprovalRequiredError, ToolDeniedError, tainted } from "@glinr/theauth";
import { describe, expect, it, vi } from "vitest";
import { createApprovalGrants, resumeAfterApproval } from "../src/index.js";
import type { LangChainToolLike } from "../src/langchain.js";
import { guardLangChainTool } from "../src/langchain.js";
import type { MastraToolContextLike } from "../src/mastra.js";
import { guardMastraTool } from "../src/mastra.js";

type EvaluateInput = Parameters<PolicyHost["policy"]["evaluate"]>[0];
type PolicyDecision = Awaited<ReturnType<PolicyHost["policy"]["evaluate"]>>;

function decision(
	kind: "allow" | "deny" | "escalate",
	extra: Partial<PolicyDecision> = {},
): PolicyDecision {
	return {
		allowed: kind === "allow",
		decision: kind,
		effect: kind === "allow" ? "permit" : kind,
		code:
			kind === "allow" ? "allowed" : kind === "escalate" ? "approval_required" : "no_permission",
		reason: kind === "deny" ? "POLICY_DENIED" : "ok",
		cacheHit: false,
		durationMs: 0,
		...extra,
	};
}

const escalation = {
	tier: "large",
	requirement: "approval" as const,
	reason: "big",
	approvalRequestId: "req_1",
};

/** Scripted policy host that records every input. */
function host(fn: (input: EvaluateInput) => PolicyDecision) {
	const calls: EvaluateInput[] = [];
	const policy: PolicyHost = {
		policy: {
			evaluate: async (input) => {
				calls.push(input);
				return fn(input);
			},
		},
	};
	return { policy, calls };
}

function fakeLangChainTool(name = "refund") {
	const run = vi.fn(async (_input: unknown) => "done");
	// A class with a private field, like the real ones, to prove the proxy keeps `this` working.
	class Fake implements LangChainToolLike {
		#secret = "s";
		name = name;
		description = "refund an invoice";
		async invoke(input: unknown): Promise<unknown> {
			return (await run(input)) + this.#secret;
		}
	}
	return { tool: new Fake(), run };
}

describe("LangChain wrapper", () => {
	it("runs the tool on allow and keeps other properties", async () => {
		const { policy } = host(() => decision("allow"));
		const { tool, run } = fakeLangChainTool();
		const guarded = guardLangChainTool(policy, { agentId: "a1" }, tool);
		expect(guarded.description).toBe("refund an invoice");
		expect(await guarded.invoke({ amount: 5 })).toBe("dones");
		expect(run).toHaveBeenCalledOnce();
	});

	it("throws ToolDeniedError on deny and never runs the tool", async () => {
		const { policy } = host(() => decision("deny"));
		const { tool, run } = fakeLangChainTool();
		const guarded = guardLangChainTool(policy, { agentId: "a1" }, tool);
		await expect(guarded.invoke({ amount: 5 })).rejects.toBeInstanceOf(ToolDeniedError);
		expect(run).not.toHaveBeenCalled();
	});

	it("blocks a tainted argument when policy denies on provenance", async () => {
		const { policy, calls } = host((input) =>
			input.context?.provenance?.recipient?.includes("untrusted_web")
				? decision("deny", { reason: "TAINT_BLOCKED" })
				: decision("allow"),
		);
		const { tool, run } = fakeLangChainTool("send");
		const guarded = guardLangChainTool(policy, { agentId: "a1" }, tool);
		const args = { recipient: tainted("evil@example.com", "untrusted_web") };
		const err = await guarded.invoke(args).catch((e: unknown) => e);
		expect(err).toBeInstanceOf(ToolDeniedError);
		expect((err as ToolDeniedError).code).toBe("TAINT_BLOCKED");
		expect(calls[0]?.context?.provenance).toEqual({ recipient: ["untrusted_web"] });
		expect(run).not.toHaveBeenCalled();
	});

	it("throws the approval error when no interrupt is given", async () => {
		const { policy } = host(() => decision("escalate", { escalation }));
		const { tool } = fakeLangChainTool();
		const guarded = guardLangChainTool(policy, { agentId: "a1" }, tool);
		await expect(guarded.invoke({ amount: 5000 })).rejects.toBeInstanceOf(
			ToolApprovalRequiredError,
		);
	});

	it("passes the payload to interrupt and retries with the approved id", async () => {
		const { policy, calls } = host((input) =>
			input.approvalId === "req_1" ? decision("allow") : decision("escalate", { escalation }),
		);
		const { tool, run } = fakeLangChainTool();
		const interrupt = vi.fn((_payload: unknown) => ({ approved: true }));
		const guarded = guardLangChainTool(policy, { agentId: "a1", interrupt }, tool);
		// ToolNode passes a tool call object.
		const result = await guarded.invoke({
			type: "tool_call",
			name: "refund",
			args: { amount: 5000 },
			id: "c1",
		});
		expect(result).toBe("dones");
		expect(interrupt).toHaveBeenCalledWith(
			expect.objectContaining({
				type: "theauth_approval_required",
				toolName: "refund",
				approvalRequestId: "req_1",
				args: { amount: 5000 },
			}),
		);
		expect(calls.at(-1)?.approvalId).toBe("req_1");
		expect(run).toHaveBeenCalledOnce();
	});

	it("denies when the human rejects", async () => {
		const { policy } = host(() => decision("escalate", { escalation }));
		const { tool, run } = fakeLangChainTool();
		const guarded = guardLangChainTool(policy, { agentId: "a1", interrupt: () => false }, tool);
		const err = await guarded.invoke({ amount: 1 }).catch((e: unknown) => e);
		expect(err).toBeInstanceOf(ToolDeniedError);
		expect((err as ToolDeniedError).code).toBe("APPROVAL_REJECTED");
		expect(run).not.toHaveBeenCalled();
	});

	it("propagates the pause when interrupt itself throws", async () => {
		const { policy } = host(() => decision("escalate", { escalation }));
		const { tool } = fakeLangChainTool();
		const pause = new Error("GraphInterrupt");
		const guarded = guardLangChainTool(
			policy,
			{
				agentId: "a1",
				interrupt: () => {
					throw pause;
				},
			},
			tool,
		);
		await expect(guarded.invoke({})).rejects.toBe(pause);
	});
});

function fakeMastraTool() {
	const run = vi.fn(async (_input: unknown, _context?: unknown) => ({ refunded: true }));
	return {
		tool: { id: "refund", description: "refund", execute: run },
		run,
	};
}

describe("Mastra wrapper", () => {
	it("allows and runs execute with the original arguments", async () => {
		const { policy } = host(() => decision("allow"));
		const { tool, run } = fakeMastraTool();
		const guarded = guardMastraTool(policy, { agentId: "a1" }, tool);
		const ctx: MastraToolContextLike = {};
		expect(await guarded.execute?.({ amount: 5 } as never, ctx as never)).toEqual({
			refunded: true,
		});
		expect(run).toHaveBeenCalledWith({ amount: 5 }, ctx);
		expect(guarded.description).toBe("refund");
	});

	it("denies without running", async () => {
		const { policy } = host(() => decision("deny"));
		const { tool, run } = fakeMastraTool();
		const guarded = guardMastraTool(policy, { agentId: "a1" }, tool);
		await expect(guarded.execute?.({ amount: 5 } as never)).rejects.toBeInstanceOf(ToolDeniedError);
		expect(run).not.toHaveBeenCalled();
	});

	it("blocks a tainted argument", async () => {
		const { policy } = host((input) =>
			input.context?.provenance ? decision("deny", { reason: "TAINT_BLOCKED" }) : decision("allow"),
		);
		const { tool, run } = fakeMastraTool();
		const guarded = guardMastraTool(policy, { agentId: "a1" }, tool);
		await expect(
			guarded.execute?.({ to: tainted("x", "untrusted_web") } as never),
		).rejects.toMatchObject({ code: "TAINT_BLOCKED" });
		expect(run).not.toHaveBeenCalled();
	});

	it("suspends on escalate, then retries on resume with the approved id", async () => {
		const { policy, calls } = host((input) =>
			input.approvalId === "req_1" ? decision("allow") : decision("escalate", { escalation }),
		);
		const { tool, run } = fakeMastraTool();
		const guarded = guardMastraTool(policy, { agentId: "a1" }, tool);
		const suspend = vi.fn(async (_payload: unknown) => undefined);

		const first = await guarded.execute?.({ amount: 5000 } as never, { suspend } as never);
		expect(first).toBeUndefined();
		expect(suspend).toHaveBeenCalledWith(
			expect.objectContaining({ approvalRequestId: "req_1", toolName: "refund" }),
		);
		expect(run).not.toHaveBeenCalled();

		const resumed = await guarded.execute?.(
			{ amount: 5000 } as never,
			{ suspend, resumeData: { approved: true, approvalRequestId: "req_1" } } as never,
		);
		expect(resumed).toEqual({ refunded: true });
		expect(calls.at(-1)?.approvalId).toBe("req_1");
	});

	it.each([
		"agent",
		"workflow",
	] as const)("suspends and resumes through the nested %s context Mastra 1.x passes", async (key) => {
		const { policy, calls } = host((input) =>
			input.approvalId === "req_1" ? decision("allow") : decision("escalate", { escalation }),
		);
		const { tool, run } = fakeMastraTool();
		const guarded = guardMastraTool(policy, { agentId: "a1" }, tool);
		const suspend = vi.fn(async (_payload: unknown) => undefined);

		await guarded.execute?.({ amount: 5000 } as never, { [key]: { suspend } } as never);
		expect(suspend).toHaveBeenCalledWith(expect.objectContaining({ approvalRequestId: "req_1" }));
		expect(run).not.toHaveBeenCalled();

		// A bare { approved: true } resume carries no id: it is read from the suspend payload.
		const resumed = await guarded.execute?.(
			{ amount: 5000 } as never,
			{
				[key]: {
					suspend,
					resumeData: { approved: true },
					suspendPayload: { approvalRequestId: "req_1" },
				},
			} as never,
		);
		expect(resumed).toEqual({ refunded: true });
		expect(calls.at(-1)?.approvalId).toBe("req_1");
	});

	it("denies on a rejected resume and throws when suspend is unavailable", async () => {
		const { policy } = host(() => decision("escalate", { escalation }));
		const { tool } = fakeMastraTool();
		const guarded = guardMastraTool(policy, { agentId: "a1" }, tool);
		await expect(
			guarded.execute?.({} as never, { resumeData: { approved: false } } as never),
		).rejects.toMatchObject({ code: "APPROVAL_REJECTED" });
		await expect(guarded.execute?.({} as never, {} as never)).rejects.toBeInstanceOf(
			ToolApprovalRequiredError,
		);
	});
});

describe("resumeAfterApproval", () => {
	const hostWith = (statuses: string[]) => {
		let i = 0;
		return {
			approval: {
				get: async () => {
					const status = statuses[Math.min(i++, statuses.length - 1)];
					return status ? { status } : null;
				},
			},
		};
	};

	it("returns the id once approved and stores a single-use grant", async () => {
		const grants = createApprovalGrants();
		const result = await resumeAfterApproval(hostWith(["approved"]), "req_9", {
			grants,
			call: { toolName: "refund", args: { b: 1, a: 2 } },
		});
		expect(result).toEqual({ status: "approved", approvalId: "req_9" });
		const take = grants.approvalIdFor("refund");
		expect(take(undefined, { a: 2, b: 1 })).toBe("req_9");
		expect(take(undefined, { a: 2, b: 1 })).toBeUndefined();
	});

	it("reports pending, denied, expired and missing requests", async () => {
		expect((await resumeAfterApproval(hostWith(["pending"]), "r")).status).toBe("pending");
		expect((await resumeAfterApproval(hostWith(["denied"]), "r")).status).toBe("denied");
		expect((await resumeAfterApproval(hostWith(["expired"]), "r")).status).toBe("expired");
		expect((await resumeAfterApproval(hostWith([]), "r")).status).toBe("not_found");
	});

	it("waits for a pending request", async () => {
		const sleep = vi.fn(async () => undefined);
		const result = await resumeAfterApproval(hostWith(["pending", "pending", "approved"]), "r", {
			waitMs: 5000,
			pollMs: 1000,
			sleep,
		});
		expect(result.status).toBe("approved");
		expect(sleep).toHaveBeenCalledTimes(2);
	});
});
