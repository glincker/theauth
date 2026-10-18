// Shared gate for the framework integrations. Structural types only: no framework is imported.

/** Machine-readable outcome, see `DECISION_CODES`. Other strings are allowed so older servers still type check. */
export type GateCode = string;

/** The slice of an `AuthorizeResult` the gate reads. */
export interface AuthorizeResultLike {
	allowed: boolean;
	reason?: string;
	code?: GateCode;
	auditId?: string;
}

export interface AuthorizeRequestLike {
	action: string;
	resource: string;
	arguments?: Record<string, unknown>;
	approvalId?: string;
}

/** Matches `theauth.authorize`. */
export type AuthorizeLike = (
	agentId: string,
	request: AuthorizeRequestLike,
) => Promise<AuthorizeResultLike>;

/** Structured refusal handed back to the model in place of the tool result. */
export interface ToolDenial {
	ok: false;
	denied: true;
	toolName: string;
	/** Decision code, or `guard_error` when the check itself failed (the gate fails closed). */
	code: GateCode;
	reason: string;
	/** True when a human could allow the call. The model should ask the user, not retry. */
	approvalRequired: boolean;
	auditId?: string;
}

export interface ApprovalRequest {
	toolName: string;
	agentId: string;
	action: string;
	resource: string;
	arguments?: Record<string, unknown>;
	auditId?: string;
}

export interface GateOptions<C = unknown> {
	/** `theauth.authorize`, or any function with the same shape. */
	authorize: AuthorizeLike;
	/** Agent id, or a function from the call context to the agent id. */
	agentId: string | ((ctx: C | undefined) => string | undefined);
	/** Action checked. Default `execute`. */
	action?: string;
	/** Resource checked. Default `tool:<name>`. */
	resource?: (toolName: string, args: Record<string, unknown> | undefined) => string;
	/**
	 * Called when the decision is `approval_required`. Return the id of an approved request to retry once with it, or undefined to refuse. Typically it opens a request, waits for a human, and returns the approved id.
	 */
	requestApproval?: (request: ApprovalRequest) => Promise<string | undefined> | string | undefined;
	/** Called with every final outcome, for logging. Errors thrown here are ignored. */
	onDecision?: (info: { toolName: string; denial: ToolDenial | null }) => void | Promise<void>;
}

export interface Gate<C = unknown> {
	/** Returns null when the call may run, or the denial to return to the model. Never throws. */
	check(toolName: string, args: unknown, ctx?: C): Promise<ToolDenial | null>;
}

const APPROVAL_REQUIRED = "approval_required";

function asRecord(args: unknown): Record<string, unknown> | undefined {
	return args !== null && typeof args === "object" && !Array.isArray(args)
		? (args as Record<string, unknown>)
		: undefined;
}

function denial(
	toolName: string,
	result: { code?: GateCode; reason?: string; auditId?: string },
): ToolDenial {
	const code = result.code ?? "no_permission";
	return {
		ok: false,
		denied: true,
		toolName,
		code,
		reason: result.reason ?? "Denied by policy",
		approvalRequired: code === APPROVAL_REQUIRED,
		...(result.auditId ? { auditId: result.auditId } : {}),
	};
}

export function createGate<C = unknown>(options: GateOptions<C>): Gate<C> {
	const action = options.action ?? "execute";

	async function decide(
		toolName: string,
		args: unknown,
		ctx: C | undefined,
	): Promise<ToolDenial | null> {
		const agentId = typeof options.agentId === "function" ? options.agentId(ctx) : options.agentId;
		if (!agentId)
			return denial(toolName, { code: "guard_error", reason: "No agent id for this call" });
		const record = asRecord(args);
		const resource = options.resource ? options.resource(toolName, record) : `tool:${toolName}`;
		const request: AuthorizeRequestLike = {
			action,
			resource,
			...(record ? { arguments: record } : {}),
		};
		let result = await options.authorize(agentId, request);
		if (result.allowed) return null;
		if (result.code === APPROVAL_REQUIRED && options.requestApproval) {
			const approvalId = await options.requestApproval({
				toolName,
				agentId,
				action,
				resource,
				...(record ? { arguments: record } : {}),
				...(result.auditId ? { auditId: result.auditId } : {}),
			});
			if (approvalId) {
				result = await options.authorize(agentId, { ...request, approvalId });
				if (result.allowed) return null;
			}
		}
		return denial(toolName, result);
	}

	return {
		async check(toolName, args, ctx) {
			let outcome: ToolDenial | null;
			try {
				outcome = await decide(toolName, args, ctx);
			} catch (error) {
				outcome = denial(toolName, {
					code: "guard_error",
					reason: error instanceof Error ? error.message : "Authorization check failed",
				});
			}
			try {
				await options.onDecision?.({ toolName, denial: outcome });
			} catch {
				// Logging must not change the outcome.
			}
			return outcome;
		},
	};
}

/** Type guard for the value a guarded tool returns when it was refused. */
export function isToolDenial(value: unknown): value is ToolDenial {
	return (
		value !== null &&
		typeof value === "object" &&
		(value as { denied?: unknown }).denied === true &&
		(value as { ok?: unknown }).ok === false
	);
}
