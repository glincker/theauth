// Opt-in: runs against the REAL @langchain/langgraph and @langchain/core.
// Enable with THEAUTH_FRAMEWORK_INTEGRATION=1 (see `pnpm test:integration`).
// The real packages are imported inside each test so the default `vitest run` never loads them.

import type { PolicyHost } from "@glinr/theauth";
import { describe, expect, it } from "vitest";
import { guardLangChainTool } from "../../src/langchain.js";

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

describe.skipIf(!enabled)("LangGraph integration (real @langchain/langgraph)", () => {
	it("pauses the graph on escalation and runs the tool once after resume", async () => {
		const { StateGraph, Annotation, MemorySaver, Command, START, END, interrupt } = await import(
			"@langchain/langgraph"
		);
		const { tool } = await import("@langchain/core/tools");
		const { z } = await import("zod");

		let runs = 0;
		const refund = tool(
			async ({ amount }: { amount: number }) => {
				runs++;
				return `refunded ${amount}`;
			},
			{
				name: "refund",
				description: "refund",
				schema: z.object({ amount: z.number() }),
			},
		);
		const guarded = guardLangChainTool(
			approvalPolicy(),
			{ agentId: "a1", interrupt: interrupt as never },
			refund,
		);

		const State = Annotation.Root({ out: Annotation<string>() });
		const graph = new StateGraph(State)
			.addNode("tools", async () => ({
				out: String(
					await guarded
						.invoke({ type: "tool_call", name: "refund", args: { amount: 5000 }, id: "c1" })
						.then((r: unknown) => (r as { content?: unknown })?.content ?? r),
				),
			}))
			.addEdge(START, "tools")
			.addEdge("tools", END)
			.compile({ checkpointer: new MemorySaver() });

		const config = { configurable: { thread_id: "t-tool-node" } };
		const paused = (await graph.invoke({}, config)) as { __interrupt__?: unknown[] };
		expect(paused.__interrupt__).toHaveLength(1);
		expect(runs).toBe(0);

		const resumed = (await graph.invoke(
			new Command({ resume: { approved: true, approvalRequestId: APPROVAL_ID } }),
			config,
		)) as { out?: string };
		expect(resumed.out).toContain("refunded 5000");
		expect(runs).toBe(1);
	});

	it("resumes a ToolNode inside a message graph without re-running the tool", async () => {
		const { StateGraph, MessagesAnnotation, MemorySaver, Command, START, END, interrupt } =
			await import("@langchain/langgraph");
		const { ToolNode } = await import("@langchain/langgraph/prebuilt");
		const { tool } = await import("@langchain/core/tools");
		const { AIMessage, HumanMessage } = await import("@langchain/core/messages");
		const { z } = await import("zod");

		let runs = 0;
		const refund = tool(
			async ({ amount }: { amount: number }) => {
				runs++;
				return `refunded ${amount}`;
			},
			{
				name: "refund",
				description: "refund",
				schema: z.object({ amount: z.number() }),
			},
		);
		const guarded = guardLangChainTool(
			approvalPolicy(),
			{ agentId: "a1", interrupt: interrupt as never },
			refund,
		);

		const graph = new StateGraph(MessagesAnnotation)
			.addNode("agent", async () => ({
				messages: [
					new AIMessage({
						content: "",
						tool_calls: [{ name: "refund", args: { amount: 5000 }, id: "c1", type: "tool_call" }],
					}),
				],
			}))
			.addNode("tools", new ToolNode([guarded as never]))
			.addEdge(START, "agent")
			.addEdge("agent", "tools")
			.addEdge("tools", END)
			.compile({ checkpointer: new MemorySaver() });

		const config = { configurable: { thread_id: "t-message-graph" } };
		const paused = (await graph.invoke(
			{ messages: [new HumanMessage("refund 5000")] },
			config,
		)) as {
			__interrupt__?: unknown[];
		};
		expect(paused.__interrupt__).toHaveLength(1);
		expect(runs).toBe(0);

		const resumed = (await graph.invoke(
			new Command({ resume: { approved: true, approvalRequestId: APPROVAL_ID } }),
			config,
		)) as { messages: { content: unknown }[] };
		expect(resumed.messages.at(-1)?.content).toBe("refunded 5000");
		expect(runs).toBe(1);
	});
});
