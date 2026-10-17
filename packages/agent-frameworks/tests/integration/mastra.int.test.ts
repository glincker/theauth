// Opt-in: runs against the REAL @mastra/core.
// Enable with THEAUTH_FRAMEWORK_INTEGRATION=1 (see `pnpm test:integration`).
// The real packages are imported inside each test so the default `vitest run` never loads them.

import type { PolicyHost } from "@glinr/theauth";
import { describe, expect, it } from "vitest";
import { guardMastraTool } from "../../src/mastra.js";

type Decision = Awaited<ReturnType<PolicyHost["policy"]["evaluate"]>>;

const APPROVAL_ID = "req_1";

const allow: Decision = {
	allowed: true,
	decision: "allow",
	effect: "permit",
	reason: "ok",
	cacheHit: false,
	durationMs: 0,
};

const escalate: Decision = {
	allowed: false,
	decision: "escalate",
	effect: "escalate",
	reason: "big",
	cacheHit: false,
	durationMs: 0,
	escalation: {
		tier: "large",
		requirement: "approval",
		reason: "big",
		approvalRequestId: APPROVAL_ID,
	},
};

/** Policy that escalates until the approved request id is presented, then allows. */
function approvalPolicy(): PolicyHost {
	const policy: PolicyHost = {
		policy: {
			evaluate: async (input) => (input.approvalId === APPROVAL_ID ? allow : escalate),
		},
	};
	return policy;
}

/** Opt-in switch. Read through globalThis so this file typechecks without @types/node. */
const enabled =
	(globalThis as { process?: { env?: Record<string, string | undefined> } }).process?.env
		?.THEAUTH_FRAMEWORK_INTEGRATION === "1";

describe.skipIf(!enabled)("Mastra integration (real @mastra/core)", () => {
	it("suspends a workflow step on escalation and runs the tool once after resume", async () => {
		const { createTool } = await import("@mastra/core/tools");
		const { createWorkflow, createStep } = await import("@mastra/core/workflows");
		const { Mastra } = await import("@mastra/core");
		const { z } = await import("zod");

		let runs = 0;
		const base = createTool({
			id: "refund",
			description: "refund",
			inputSchema: z.object({ amount: z.number() }),
			outputSchema: z.object({ refunded: z.number() }).optional(),
			suspendSchema: z.any(),
			resumeSchema: z.object({
				approved: z.boolean(),
				approvalRequestId: z.string().optional(),
			}),
			execute: async (input: { amount: number }) => {
				runs++;
				return { refunded: input.amount };
			},
		} as never);
		const guarded = guardMastraTool(approvalPolicy(), { agentId: "a1" }, base as never);

		const step = createStep(guarded as never);
		const workflow = createWorkflow({
			id: "refund-wf",
			inputSchema: z.object({ amount: z.number() }),
			outputSchema: z.any(),
		})
			.then(step as never)
			.commit();
		const mastra = new Mastra({ workflows: { "refund-wf": workflow } as never, logger: false });

		const run = await (
			mastra.getWorkflow("refund-wf") as never as {
				createRun(): Promise<{
					start(args: { inputData: unknown }): Promise<{ status: string; suspended?: unknown }>;
					resume(args: {
						step: string;
						resumeData: unknown;
					}): Promise<{ status: string; result?: unknown }>;
				}>;
			}
		).createRun();

		const first = await run.start({ inputData: { amount: 5000 } });
		expect(first.status).toBe("suspended");
		expect(runs).toBe(0);

		const second = await run.resume({
			step: "refund",
			resumeData: { approved: true, approvalRequestId: APPROVAL_ID },
		});
		expect(second.status).toBe("success");
		expect(runs).toBe(1);
	});

	it("suspends an agent tool call and resumes generation after approval", async () => {
		const { createTool } = await import("@mastra/core/tools");
		const { Mastra } = await import("@mastra/core");
		const { Agent } = await import("@mastra/core/agent");
		const { InMemoryStore } = await import("@mastra/core/storage");
		const { z } = await import("zod");

		let runs = 0;
		const base = createTool({
			id: "refund",
			description: "refund",
			inputSchema: z.object({ amount: z.number() }),
			outputSchema: z.object({ refunded: z.number() }),
			suspendSchema: z.any(),
			resumeSchema: z.object({
				approved: z.boolean(),
				approvalRequestId: z.string().optional(),
			}),
			execute: async (input: { amount: number }) => {
				runs++;
				return { refunded: input.amount };
			},
		} as never);
		const guarded = guardMastraTool(approvalPolicy(), { agentId: "a1" }, base as never);

		// Scripted language model: first turn calls the refund tool, second turn answers.
		let calls = 0;
		const usage = { inputTokens: 1, outputTokens: 1, totalTokens: 2 };
		const model = {
			specificationVersion: "v2",
			provider: "mock",
			modelId: "mock",
			supportedUrls: {},
			doGenerate: async () => {
				const first = calls++ === 0;
				return {
					content: first
						? [
								{
									type: "tool-call",
									toolCallId: "tc1",
									toolName: "refund",
									input: JSON.stringify({ amount: 5000 }),
								},
							]
						: [{ type: "text", text: "done" }],
					finishReason: first ? "tool-calls" : "stop",
					usage,
					warnings: [],
					response: { id: "r", modelId: "mock", timestamp: new Date() },
				};
			},
			doStream: async () => {
				throw new Error("doStream is not used by this test");
			},
		};

		const agent = new Agent({
			id: "ag",
			name: "ag",
			instructions: "x",
			model,
			tools: { refund: guarded },
		} as never);
		const mastra = new Mastra({
			agents: { ag: agent },
			storage: new InMemoryStore() as never,
			logger: false,
		});

		const registered = mastra.getAgent("ag") as never as {
			generate(
				prompt: string,
				opts: { maxSteps: number },
			): Promise<{ finishReason?: string; runId?: string; text?: string }>;
			resumeGenerate(
				data: unknown,
				opts: { runId?: string; toolCallId: string },
			): Promise<{ text?: string }>;
		};
		const out = await registered.generate("refund 5000", { maxSteps: 3 });
		expect(out.finishReason).toBe("suspended");
		expect(runs).toBe(0);

		const resumed = await registered.resumeGenerate(
			{ approved: true, approvalRequestId: APPROVAL_ID },
			{ runId: out.runId, toolCallId: "tc1" },
		);
		expect(resumed.text).toBe("done");
		expect(runs).toBe(1);
	});
});
