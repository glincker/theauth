// Framework-agnostic guard: put theAuth policy in front of an agent tool.
// No framework imports. A tool is any object with an `execute` function.

import type {
	EvaluateInput,
	EvaluateOptions,
	PolicyDecision,
	RiskContext,
} from "../policy/types.js";
import type { ProvenanceTracker } from "../taint/labels.js";
import { labelsOf, mergeProvenance, TaintedValue } from "../taint/labels.js";
import type { ProvenanceMap } from "../taint/types.js";
import { ToolApprovalRequiredError, ToolDeniedError, ToolGuardFailedError } from "./errors.js";

/** The slice of a theAuth instance the guard uses. */
export interface PolicyHost {
	policy: {
		evaluate(input: EvaluateInput, options?: EvaluateOptions): Promise<PolicyDecision>;
	};
}

/** Any object with an `execute` function. `name` is optional (Vercel AI SDK tools have none). */
export interface GuardableTool {
	name?: string;
	execute: (...args: never[]) => unknown;
}

type ExecuteParams<T extends GuardableTool> = Parameters<T["execute"]>;
type ArgsOf<T extends GuardableTool> = ExecuteParams<T>[0];
type CtxOf<T extends GuardableTool> = ExecuteParams<T>[1];

export interface GuardDecisionInfo<A, C> {
	toolName: string;
	agentId: string;
	args: A;
	ctx: C | undefined;
	decision: PolicyDecision;
}

export interface GuardEscalationInfo<A, C> extends GuardDecisionInfo<A, C> {
	tier: string;
	requirement: "approval" | "step_up";
	approvalRequestId?: string;
}

export interface GuardOptions<A = unknown, C = unknown> {
	/** Agent id, or a function from the call context and args to the agent id. */
	agentId: string | ((ctx: C | undefined, args: A) => string | undefined);
	/** Tool name. Needed when the tool has no `name` property. */
	name?: string;
	/** Resource checked in the policy. Default `tool:<name>`. */
	resource?: string | ((args: A) => string);
	/** Action checked in the policy. Default `execute`. */
	action?: string;
	/** Derive risk attributes (amount, currency, dataClass, irreversible) from the args. */
	risk?: (args: A) => RiskContext | undefined;
	/**
	 * Id of an approved request to spend on this call, for the retry after a human approved a ToolApprovalRequiredError. It is single use and must match this agent, action and resource, so return it only for the call that was approved.
	 */
	approvalId?: (ctx: C | undefined, args: A) => string | undefined;
	/**
	 * Provenance labels of the arguments, e.g. `{ recipient: ["untrusted_web"] }`. Use the key "*" for labels that cover the whole call. Merged with labels read from `tracker` and from values tagged with `tainted()`. With none of these, the call is evaluated as before.
	 */
	provenance?: ProvenanceMap | ((args: A, ctx: C | undefined) => ProvenanceMap | undefined);
	/** Tracker that reads labels off the arguments and registers this tool's result as `tool_output:<name>` (plus the labels of its arguments), so the output flows into the arguments of later guarded calls. */
	tracker?: ProvenanceTracker;
	/** Open an approval request when the decision escalates. Default true. */
	openApproval?: boolean;
	/** Called before ToolApprovalRequiredError is thrown, e.g. to notify an approver. Errors propagate. */
	onEscalate?: (info: GuardEscalationInfo<A, C>) => void | Promise<void>;
	/** Called with every decision, for logging. Errors thrown here are ignored. */
	onDecision?: (info: GuardDecisionInfo<A, C>) => void | Promise<void>;
}

function resolveName(tool: GuardableTool, options: { name?: string }): string {
	const name = options.name ?? tool.name;
	if (!name) {
		throw new TypeError("guardTool: the tool has no name. Pass options.name.");
	}
	return name;
}

function reasonCode(reason: string): string | undefined {
	return /^[A-Z][A-Z0-9_]{2,}$/.test(reason) ? reason : undefined;
}

function resolveProvenance<A, C>(
	options: GuardOptions<A, C>,
	args: A,
	ctx: C | undefined,
): ProvenanceMap | undefined {
	const explicit =
		typeof options.provenance === "function" ? options.provenance(args, ctx) : options.provenance;
	const found: ProvenanceMap = {};
	// A tainted primitive passed as the whole argument labels the call as a whole.
	if (args instanceof TaintedValue) {
		const wholeLabels = labelsOf(args);
		if (wholeLabels.length > 0) found["*"] = wholeLabels;
	}
	if (args !== null && typeof args === "object") {
		for (const [name, value] of Object.entries(args)) {
			const labels = labelsOf(value);
			if (labels.length > 0) found[name] = labels;
		}
	}
	const merged = mergeProvenance(explicit, options.tracker?.argLabels(args), found);
	return Object.keys(merged).length > 0 ? merged : undefined;
}

/** Unwrap TaintedValue arguments so the tool sees plain values. */
function unwrapArgs(callArgs: unknown[]): unknown[] {
	const first = callArgs[0];
	if (first instanceof TaintedValue) return [first.value, ...callArgs.slice(1)];
	if (first === null || typeof first !== "object" || Array.isArray(first)) return callArgs;
	if (!Object.values(first).some((v) => v instanceof TaintedValue)) return callArgs;
	const plain: Record<string, unknown> = {};
	for (const [k, v] of Object.entries(first)) plain[k] = v instanceof TaintedValue ? v.value : v;
	return [plain, ...callArgs.slice(1)];
}

/**
 * Wrap a tool so `execute` only runs when `theauth.policy.evaluate` allows it. Returns a new object with every other property of the tool preserved. Deny throws ToolDeniedError, escalate throws ToolApprovalRequiredError, and any failure of the check throws ToolGuardFailedError. `execute` runs only on allow.
 */
export function guardTool<T extends GuardableTool>(
	theauth: PolicyHost,
	options: GuardOptions<ArgsOf<T>, CtxOf<T>>,
	tool: T,
): T {
	const toolName = resolveName(tool, options);
	const original = tool.execute;

	const guarded = async (...callArgs: ExecuteParams<T>): Promise<unknown> => {
		const args = callArgs[0] as ArgsOf<T>;
		const ctx = callArgs[1] as CtxOf<T> | undefined;
		let agentId: string | undefined;
		let decision: PolicyDecision;
		let provenance: ProvenanceMap | undefined;
		try {
			agentId =
				typeof options.agentId === "function" ? options.agentId(ctx, args) : options.agentId;
			if (!agentId) {
				throw new Error("no agent id for this call");
			}
			const resource =
				typeof options.resource === "function"
					? options.resource(args)
					: (options.resource ?? `tool:${toolName}`);
			const risk = options.risk?.(args);
			const approvalId = options.approvalId?.(ctx, args);
			provenance = resolveProvenance(options, args, ctx);
			decision = await theauth.policy.evaluate(
				{
					subject: { agentId },
					action: options.action ?? "execute",
					resource,
					context:
						risk || provenance
							? { ...(risk ? { risk } : {}), ...(provenance ? { provenance } : {}) }
							: undefined,
					...(approvalId ? { approvalId } : {}),
				},
				{ openApproval: options.openApproval ?? true },
			);
		} catch (error) {
			throw new ToolGuardFailedError({
				toolName,
				agentId,
				reason: error instanceof Error ? error.message : "unknown error",
				cause: error,
			});
		}

		const info: GuardDecisionInfo<ArgsOf<T>, CtxOf<T>> = { toolName, agentId, args, ctx, decision };
		if (options.onDecision) {
			try {
				await options.onDecision(info);
			} catch {
				// Logging must not change the outcome.
			}
		}

		if (decision.decision === "allow") {
			const runArgs = unwrapArgs(callArgs);
			const result = await original.apply(tool, runArgs as never[]);
			if (options.tracker) {
				const inherited = [...new Set(Object.values(provenance ?? {}).flat())];
				options.tracker.trackResult(toolName, result, inherited);
			}
			return result;
		}
		if (decision.decision === "escalate") {
			const escalation = decision.escalation;
			const tier = escalation?.tier ?? "unknown";
			const requirement = escalation?.requirement ?? "approval";
			const approvalRequestId = escalation?.approvalRequestId;
			await options.onEscalate?.({ ...info, tier, requirement, approvalRequestId });
			throw new ToolApprovalRequiredError({
				toolName,
				agentId,
				reason: decision.reason,
				tier,
				requirement,
				approvalRequestId,
			});
		}
		throw new ToolDeniedError({
			toolName,
			agentId,
			reason: decision.reason,
			code: reasonCode(decision.reason),
		});
	};

	return { ...tool, execute: guarded } as T;
}

/** Guard several tools with the same options. Accepts an array of named tools or a record keyed by tool name (the Vercel AI SDK shape). For a record the key is the tool name. Returns the same shape. */
export function guardTools<T extends GuardableTool>(
	theauth: PolicyHost,
	options: GuardOptions<ArgsOf<T>, CtxOf<T>>,
	tools: T[],
): T[];
export function guardTools<T extends GuardableTool, K extends string>(
	theauth: PolicyHost,
	options: GuardOptions<ArgsOf<T>, CtxOf<T>>,
	tools: Record<K, T>,
): Record<K, T>;
export function guardTools<T extends GuardableTool>(
	theauth: PolicyHost,
	options: GuardOptions<ArgsOf<T>, CtxOf<T>>,
	tools: T[] | Record<string, T>,
): T[] | Record<string, T> {
	if (Array.isArray(tools)) {
		return tools.map((tool) => guardTool(theauth, { ...options }, tool));
	}
	const out: Record<string, T> = {};
	for (const [key, tool] of Object.entries(tools)) {
		out[key] = guardTool(theauth, { ...options, name: key }, tool);
	}
	return out;
}
