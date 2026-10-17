// LangChain.js and LangGraph wrapper. Nothing from either package is imported: the tool is
// typed structurally and `interrupt` is passed in, so they stay peer dependencies.

import type { GuardOptions, PolicyHost } from "@glinr/theauth";
import { guardTool, ToolDeniedError } from "@glinr/theauth";
import type { ApprovalInterruptPayload } from "./shared.js";
import {
	isApprovalRequired,
	normalizeDecision,
	toInterruptPayload,
	withOverride,
} from "./shared.js";

/**
 * The slice of a LangChain tool the wrapper needs. `tool()` from `@langchain/core/tools`
 * returns an object like this. `invoke` takes either the plain arguments or a tool call
 * (`{ type: "tool_call", name, args, id }`), which is what LangGraph's ToolNode passes.
 */
export interface LangChainToolLike {
	name: string;
	invoke(input: unknown, config?: unknown): Promise<unknown>;
}

export interface GuardLangChainOptions
	extends Omit<GuardOptions<unknown, unknown>, "name" | "approvalId"> {
	/**
	 * `interrupt` from `@langchain/langgraph`. When set, an escalation pauses the graph with an
	 * `ApprovalInterruptPayload`; resume with `new Command({ resume })`, where resume is `true`,
	 * `false` or `{ approved, approvalRequestId? }`. When omitted, ToolApprovalRequiredError is
	 * thrown as is (useful outside a graph).
	 */
	interrupt?: (payload: ApprovalInterruptPayload) => unknown;
	/** Spend this approved request id on the first attempt (no interrupt needed). */
	approvalId?: (config: unknown, args: unknown) => string | undefined;
}

function argsOf(input: unknown): unknown {
	if (
		input !== null &&
		typeof input === "object" &&
		(input as { type?: unknown }).type === "tool_call" &&
		"args" in input
	) {
		return (input as { args: unknown }).args;
	}
	return input;
}

/**
 * Guard a LangChain tool. The returned tool behaves like the original except `invoke` asks
 * theAuth policy first. Allow runs the tool, deny throws ToolDeniedError, and escalate calls
 * `interrupt` (see options). After a human approves, the node restarts, `interrupt` returns the
 * decision, and the wrapper retries once with the approved request id.
 *
 * Because a LangGraph node restarts on resume, the policy check runs again and may open a second
 * pending request. The approved id from the first interrupt is the one that is spent; the extra
 * request expires on its own.
 */
export function guardLangChainTool<T extends LangChainToolLike>(
	theauth: PolicyHost,
	options: GuardLangChainOptions,
	tool: T,
): T {
	const { interrupt, approvalId: initialApproval, ...guardOptions } = options;
	const toolName = tool.name;

	const invoke = async (input: unknown, config?: unknown): Promise<unknown> => {
		const args = argsOf(input);
		const attempt = (approved?: string) =>
			guardTool(
				theauth,
				{
					...guardOptions,
					name: toolName,
					approvalId: () => approved ?? initialApproval?.(config, args),
				},
				{ name: toolName, execute: (_args: unknown, _ctx: unknown) => tool.invoke(input, config) },
			).execute(args, config);

		try {
			return await attempt();
		} catch (error) {
			if (!isApprovalRequired(error) || !interrupt) throw error;
			const decision = normalizeDecision(interrupt(toInterruptPayload(error, args)));
			if (!decision.approved) {
				throw new ToolDeniedError({
					toolName,
					agentId: error.agentId,
					reason: "APPROVAL_REJECTED",
					code: "APPROVAL_REJECTED",
				});
			}
			const id = decision.approvalRequestId ?? error.approvalRequestId;
			if (!id) throw error;
			return attempt(id);
		}
	};

	return withOverride(tool, "invoke", invoke as T["invoke"]);
}

/** Guard several LangChain tools with the same options. */
export function guardLangChainTools<T extends LangChainToolLike>(
	theauth: PolicyHost,
	options: GuardLangChainOptions,
	tools: T[],
): T[] {
	return tools.map((tool) => guardLangChainTool(theauth, options, tool));
}

export type { ApprovalInterruptPayload, ResumeDecision } from "./shared.js";
