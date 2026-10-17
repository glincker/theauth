// Pieces shared by every framework wrapper: the interrupt payload, the resume
// value, a single-use grant store and `resumeAfterApproval`.

import { ToolApprovalRequiredError } from "@glinr/theauth";

/** What a human reviewer (or your UI) receives when a guarded tool call needs approval. */
export interface ApprovalInterruptPayload {
	type: "theauth_approval_required";
	toolName: string;
	agentId?: string;
	tier: string;
	requirement: "approval" | "step_up";
	/** The pending request to approve with `theauth.approval.approve(id, approverId)`. */
	approvalRequestId?: string;
	/** The tool arguments the human is asked to approve. */
	args: unknown;
	message: string;
}

/**
 * The value you resume with after a decision. A bare boolean is accepted too.
 * `approvalRequestId` defaults to the id in the interrupt payload.
 */
export type ResumeDecision = boolean | { approved: boolean; approvalRequestId?: string };

export interface NormalizedDecision {
	approved: boolean;
	approvalRequestId?: string;
}

export function isApprovalRequired(error: unknown): error is ToolApprovalRequiredError {
	return error instanceof ToolApprovalRequiredError;
}

export function toInterruptPayload(
	error: ToolApprovalRequiredError,
	args: unknown,
): ApprovalInterruptPayload {
	return {
		type: "theauth_approval_required",
		toolName: error.toolName,
		agentId: error.agentId,
		tier: error.tier,
		requirement: error.requirement,
		approvalRequestId: error.approvalRequestId,
		args,
		message: error.message,
	};
}

/** Turn whatever the resume channel returned into a decision. Anything unrecognised is a rejection. */
export function normalizeDecision(value: unknown): NormalizedDecision {
	if (value === true) return { approved: true };
	if (value !== null && typeof value === "object" && "approved" in value) {
		const { approved, approvalRequestId } = value as {
			approved: unknown;
			approvalRequestId?: unknown;
		};
		return {
			approved: approved === true,
			approvalRequestId: typeof approvalRequestId === "string" ? approvalRequestId : undefined,
		};
	}
	return { approved: false };
}

function stableStringify(value: unknown): string {
	if (value === null || typeof value !== "object") return JSON.stringify(value) ?? "undefined";
	if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
	const entries = Object.entries(value as Record<string, unknown>)
		.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
		.map(([k, v]) => `${JSON.stringify(k)}:${stableStringify(v)}`);
	return `{${entries.join(",")}}`;
}

/**
 * Remembers approved request ids until the matching retry spends them. Use it as the
 * guard's `approvalId` option for frameworks that retry in a fresh request (Vercel AI SDK,
 * OpenAI Agents SDK). Entries are keyed by tool name and arguments, and `approvalId` removes
 * the entry it returns, so one approval is offered once.
 */
export interface ApprovalGrants {
	grant(toolName: string, args: unknown, approvalRequestId: string): void;
	/** Pass as `approvalId` in the guard options. Name is the tool's name. */
	approvalIdFor(toolName: string): (ctx: unknown, args: unknown) => string | undefined;
	size(): number;
}

export function createApprovalGrants(): ApprovalGrants {
	const grants = new Map<string, string>();
	const key = (toolName: string, args: unknown) => `${toolName}\u0000${stableStringify(args)}`;
	return {
		grant(toolName, args, approvalRequestId) {
			grants.set(key(toolName, args), approvalRequestId);
		},
		approvalIdFor(toolName) {
			return (_ctx, args) => {
				const k = key(toolName, args);
				const id = grants.get(k);
				if (id !== undefined) grants.delete(k);
				return id;
			};
		},
		size: () => grants.size,
	};
}

/** The slice of a theAuth instance `resumeAfterApproval` reads. */
export interface ApprovalHost {
	approval: {
		get(requestId: string): Promise<{ status: string } | null>;
	};
}

export type ResumeResult =
	| { status: "approved"; approvalId: string }
	| { status: "pending" | "denied" | "expired" | "not_found"; approvalId?: undefined };

export interface ResumeAfterApprovalOptions {
	/** Keep checking for this long when the request is still pending. Default 0 (check once). */
	waitMs?: number;
	/** Delay between checks while waiting. Default 1000. */
	pollMs?: number;
	/** When set, an approved request is stored here so the retry spends it. */
	grants?: ApprovalGrants;
	/** Required with `grants`: the tool name and exact arguments of the held call. */
	call?: { toolName: string; args: unknown };
	/** Replace the timer, for tests. */
	sleep?: (ms: number) => Promise<void>;
}

/**
 * Check an approval request opened by a held tool call. If a human approved it, returns the id
 * to hand to the guard's `approvalId` option on the retry, and stores it in `grants` when given.
 * The guard still verifies the request (same agent, action, resource, single use) when it spends it.
 */
export async function resumeAfterApproval(
	theauth: ApprovalHost,
	approvalRequestId: string,
	options: ResumeAfterApprovalOptions = {},
): Promise<ResumeResult> {
	const waitMs = options.waitMs ?? 0;
	const pollMs = Math.max(1, options.pollMs ?? 1000);
	const sleep = options.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
	let waited = 0;
	for (;;) {
		const request = await theauth.approval.get(approvalRequestId);
		if (!request) return { status: "not_found" };
		if (request.status === "approved") {
			if (options.grants && options.call) {
				options.grants.grant(options.call.toolName, options.call.args, approvalRequestId);
			}
			return { status: "approved", approvalId: approvalRequestId };
		}
		if (request.status === "denied") return { status: "denied" };
		if (request.status === "expired") return { status: "expired" };
		if (waited >= waitMs) return { status: "pending" };
		await sleep(pollMs);
		waited += pollMs;
	}
}

/**
 * Return a view of `tool` with one property replaced. Methods are bound to the original
 * so classes with private fields keep working.
 */
export function withOverride<T extends object, K extends keyof T>(
	tool: T,
	key: K,
	replacement: T[K],
): T {
	return new Proxy(tool, {
		get(target, prop) {
			if (prop === key) return replacement;
			const value = Reflect.get(target, prop, target) as unknown;
			return typeof value === "function"
				? (value as (...a: unknown[]) => unknown).bind(target)
				: value;
		},
	});
}
