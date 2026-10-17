import type { DecisionCode, ViolationType } from "../permission/codes.js";
import type { AgentIdentity, CreateAgentInput } from "../types.js";

export type { ViolationType };

export interface TheAuthHooks {
	/** Fires before authorize(), can block the request by returning `{ allow: false, reason: '...' }`. Return `void` or `{ allow: true }` to let the request proceed. */
	beforeAuthorize?: (context: {
		agentId: string;
		action: string;
		resource: string;
		arguments?: Record<string, unknown>;
	}) => Promise<{ allow: boolean; reason?: string } | undefined>;

	/** Fires after authorize() with the final result. */
	afterAuthorize?: (context: {
		agentId: string;
		action: string;
		resource: string;
		result: { allowed: boolean; reason?: string; auditId: string; code?: DecisionCode };
	}) => Promise<void>;

	/** Fires before agent creation, return `{ allow: false }` to block. */
	beforeAgentCreate?: (
		input: CreateAgentInput,
	) => Promise<{ allow: boolean; reason?: string } | undefined>;

	/** Fires after an agent is successfully created. */
	afterAgentCreate?: (agent: AgentIdentity) => Promise<void>;

	/** Fires when an agent is revoked. */
	onAgentRevoke?: (agentId: string) => Promise<void>;

	/** Fires when a policy violation is detected (denied, rate-limited, etc.). */
	onViolation?: (violation: {
		/** Coarse grouping of `code`. */
		type: ViolationType;
		/** Machine-readable denial code. Prefer this over `type` and `reason`. */
		code: DecisionCode;
		agentId: string;
		action: string;
		resource: string;
		reason: string;
	}) => Promise<void>;
}

/** @deprecated Use `TheAuthHooks` instead. Will be removed in a future major version. */
export type AuthHooks = TheAuthHooks;

/**
 * Map an authorization denial reason string to a violation type by substring match. Falls back to 'permission_denied' when no more specific match is found.
 * @deprecated Substring matching misclassifies reasons that contain a name such as "pirate". Use `result.code` or the `code` passed to `onViolation`, and `violationTypeOf(code)` for the coarse type.
 */
export function classifyViolation(reason: string | undefined): ViolationType {
	const r = reason?.toLowerCase() ?? "";
	if (r.includes("rate") || r.includes("rate_limited")) return "rate_limited";
	if (r.includes("ip") || r.includes("allowlist")) return "ip_blocked";
	if (r.includes("time") || r.includes("window")) return "time_restricted";
	if (r.includes("approval")) return "approval_required";
	return "permission_denied";
}
