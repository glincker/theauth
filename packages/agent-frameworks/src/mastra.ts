// Mastra wrapper. Nothing from @mastra/core is imported: the tool is typed structurally.

import type { GuardOptions, PolicyHost } from "@glinr/theauth";
import { guardTool, ToolDeniedError } from "@glinr/theauth";
import {
	isApprovalRequired,
	normalizeDecision,
	toInterruptPayload,
	withOverride,
} from "./shared.js";

export interface MastraToolContextLike {
	/** Present while a tool can pause for input. Resumed runs see `resumeData`. */
	suspend?: (payload: unknown) => Promise<unknown>;
	resumeData?: unknown;
	/** Mastra 1.x nests these under `agent` (Agent runs) or `workflow` (workflow steps). */
	agent?: {
		suspend?: (payload: unknown) => Promise<unknown>;
		resumeData?: unknown;
		suspendPayload?: unknown;
	};
	workflow?: {
		suspend?: (payload: unknown) => Promise<unknown>;
		resumeData?: unknown;
		suspendPayload?: unknown;
	};
	[key: string]: unknown;
}

/** A tool made with `createTool` from `@mastra/core/tools`. */
export interface MastraToolLike {
	id: string;
	execute?: (inputData: never, context?: never) => unknown;
}

export interface GuardMastraOptions
	extends Omit<GuardOptions<unknown, MastraToolContextLike | undefined>, "name" | "approvalId"> {
	/**
	 * What to do on escalation. "suspend" (default) calls `context.suspend` with an
	 * `ApprovalInterruptPayload` when Mastra provided it, and falls back to throwing
	 * ToolApprovalRequiredError when it did not. "throw" always throws.
	 */
	onApprovalRequired?: "suspend" | "throw";
	/** Mastra versions before 1.0 passed `{ context }` as the first argument. Set true to read args from it. */
	legacyContextArg?: boolean;
}

/**
 * Guard a Mastra tool. Allow runs the original `execute`, deny throws ToolDeniedError. On
 * escalation the run is suspended with the approval payload. Give the tool a `resumeSchema` of
 * `{ approved: boolean, approvalRequestId?: string }` so Mastra accepts that resume data. When it
 * resumes, `execute` runs again, sees `context.resumeData`, and retries once with the approved
 * request id.
 */
export function guardMastraTool<T extends MastraToolLike>(
	theauth: PolicyHost,
	options: GuardMastraOptions,
	tool: T,
): T {
	const original = tool.execute;
	if (!original) {
		throw new TypeError(`guardMastraTool: tool "${tool.id}" has no execute function.`);
	}
	const { onApprovalRequired = "suspend", legacyContextArg = false, ...guardOptions } = options;
	const toolName = tool.id;
	const run = original as (first: unknown, context?: unknown) => unknown;

	const execute = async (first: unknown, context?: MastraToolContextLike): Promise<unknown> => {
		const args = legacyContextArg ? (first as { context?: unknown } | null)?.context : first;
		const ctx = legacyContextArg ? (first as MastraToolContextLike) : context;
		const attempt = (approved?: string) =>
			guardTool(
				theauth,
				{ ...guardOptions, name: toolName, approvalId: () => approved },
				{
					name: toolName,
					execute: (_args: unknown, _ctx: MastraToolContextLike | undefined) =>
						Promise.resolve(run.call(tool, first, context)),
				},
			).execute(args, ctx);

		const suspendFn = ctx?.suspend ?? ctx?.agent?.suspend ?? ctx?.workflow?.suspend;
		const resume = ctx?.resumeData ?? ctx?.agent?.resumeData ?? ctx?.workflow?.resumeData;
		if (resume !== undefined) {
			const decision = normalizeDecision(resume);
			if (!decision.approved) {
				throw new ToolDeniedError({
					toolName,
					reason: "APPROVAL_REJECTED",
					code: "APPROVAL_REJECTED",
				});
			}
			const prior = (ctx?.agent?.suspendPayload ?? ctx?.workflow?.suspendPayload) as
				| { approvalRequestId?: string; suspendPayload?: { approvalRequestId?: string } }
				| undefined;
			const id =
				decision.approvalRequestId ??
				prior?.approvalRequestId ??
				prior?.suspendPayload?.approvalRequestId;
			if (id) return attempt(id);
		}

		try {
			return await attempt();
		} catch (error) {
			if (!isApprovalRequired(error) || onApprovalRequired === "throw" || !suspendFn) {
				throw error;
			}
			await suspendFn(toInterruptPayload(error, args));
			return undefined;
		}
	};

	return withOverride(tool, "execute", execute as T["execute"]);
}

/** Guard a record of Mastra tools (the shape an Agent's `tools` option takes). Keys are kept. */
export function guardMastraTools<T extends MastraToolLike>(
	theauth: PolicyHost,
	options: GuardMastraOptions,
	tools: Record<string, T>,
): Record<string, T> {
	const out: Record<string, T> = {};
	for (const [key, tool] of Object.entries(tools))
		out[key] = guardMastraTool(theauth, options, tool);
	return out;
}

export type { ApprovalInterruptPayload, ResumeDecision } from "./shared.js";
