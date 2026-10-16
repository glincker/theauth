// Typed errors thrown by guarded agent tools. Messages are written to be shown
// to the model as a tool error, so they say what happened and what to do next.

export type ToolGuardErrorCode =
	| "TOOL_DENIED"
	| "TOOL_APPROVAL_REQUIRED"
	| "TOOL_GUARD_FAILED"
	| (string & {});

export interface ToolGuardErrorInit {
	toolName: string;
	agentId?: string;
	code: ToolGuardErrorCode;
	reason: string;
	cause?: unknown;
}

/** Base class. Check `instanceof ToolGuardError` to catch every guard refusal. */
export class ToolGuardError extends Error {
	readonly code: ToolGuardErrorCode;
	readonly toolName: string;
	readonly agentId?: string;
	readonly reason: string;

	constructor(message: string, init: ToolGuardErrorInit) {
		super(message, init.cause === undefined ? undefined : { cause: init.cause });
		this.name = "ToolGuardError";
		this.code = init.code;
		this.toolName = init.toolName;
		this.agentId = init.agentId;
		this.reason = init.reason;
	}
}

/** The policy denied the call. `execute` did not run. */
export class ToolDeniedError extends ToolGuardError {
	constructor(init: Omit<ToolGuardErrorInit, "code"> & { code?: ToolGuardErrorCode }) {
		const code = init.code ?? "TOOL_DENIED";
		super(`Tool "${init.toolName}" was denied by policy (${code}). Do not retry this call.`, {
			...init,
			code,
		});
		this.name = "ToolDeniedError";
	}
}

export interface ToolApprovalRequiredInit extends Omit<ToolGuardErrorInit, "code"> {
	tier: string;
	requirement: "approval" | "step_up";
	/** Set when an approval request was opened for this call. */
	approvalRequestId?: string;
}

/** The call needs a human to approve first. `execute` did not run. */
export class ToolApprovalRequiredError extends ToolGuardError {
	readonly tier: string;
	readonly requirement: "approval" | "step_up";
	readonly approvalRequestId?: string;

	constructor(init: ToolApprovalRequiredInit) {
		const ref = init.approvalRequestId
			? ` Approval request ${init.approvalRequestId} was opened.`
			: "";
		super(
			`Tool "${init.toolName}" needs human ${init.requirement === "step_up" ? "step-up" : "approval"} (tier ${init.tier}).${ref} Do not retry until it is granted; tell the user it is waiting.`,
			{ ...init, code: "TOOL_APPROVAL_REQUIRED" },
		);
		this.name = "ToolApprovalRequiredError";
		this.tier = init.tier;
		this.requirement = init.requirement;
		this.approvalRequestId = init.approvalRequestId;
	}
}

/** The check itself failed (policy, audit, risk callback or missing agent id). Fail closed. */
export class ToolGuardFailedError extends ToolGuardError {
	constructor(init: Omit<ToolGuardErrorInit, "code">) {
		super(`Tool "${init.toolName}" was blocked because the policy check could not complete.`, {
			...init,
			code: "TOOL_GUARD_FAILED",
		});
		this.name = "ToolGuardFailedError";
	}
}
