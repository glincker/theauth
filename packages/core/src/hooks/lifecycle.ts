import type { AgentIdentity, CreateAgentInput } from "../types.js";

export interface TheAuthHooks {
	/**
	 * Fires before authorize() — can block the request by returning
	 * `{ allow: false, reason: '...' }`. Return `void` or `{ allow: true }`
	 * to let the request proceed.
	 */
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
		result: { allowed: boolean; reason?: string; auditId: string };
	}) => Promise<void>;

	/** Fires before agent creation — return `{ allow: false }` to block. */
	beforeAgentCreate?: (
		input: CreateAgentInput,
	) => Promise<{ allow: boolean; reason?: string } | undefined>;

	/** Fires after an agent is successfully created. */
	afterAgentCreate?: (agent: AgentIdentity) => Promise<void>;

	/** Fires when an agent is revoked. */
	onAgentRevoke?: (agentId: string) => Promise<void>;

	/**
	 * Fires when a policy violation is detected (denied, rate-limited, etc.).
	 */
	onViolation?: (violation: {
		type:
			| "permission_denied"
			| "rate_limited"
			| "ip_blocked"
			| "time_restricted"
			| "approval_required";
		agentId: string;
		action: string;
		resource: string;
		reason: string;
	}) => Promise<void>;
}

/** @deprecated Use `TheAuthHooks` instead. Will be removed in a future major version. */
export type AuthHooks = TheAuthHooks;

/** @deprecated Use `TheAuthHooks` instead. Will be removed in a future major version. */
export type KavachHooks = TheAuthHooks;

export type ViolationType =
	| "permission_denied"
	| "rate_limited"
	| "ip_blocked"
	| "time_restricted"
	| "approval_required";

/**
 * Map an authorization denial reason string to a violation type.
 * Falls back to 'permission_denied' when no more specific match is found.
 */
export function classifyViolation(reason: string | undefined): ViolationType {
	const r = reason?.toLowerCase() ?? "";
	if (r.includes("rate") || r.includes("rate_limited")) return "rate_limited";
	if (r.includes("ip") || r.includes("allowlist")) return "ip_blocked";
	if (r.includes("time") || r.includes("window")) return "time_restricted";
	if (r.includes("approval")) return "approval_required";
	return "permission_denied";
}
