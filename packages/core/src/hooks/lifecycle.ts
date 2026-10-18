import type { DecisionCode, ViolationType } from "../permission/codes.js";
import type { AgentIdentity, CreateAgentInput, Permission, RequestContext } from "../types.js";

export type { ViolationType };

/** One delegation grant, from `fromAgent` to `toAgent`. */
export interface DelegationLink {
	delegationId: string;
	fromAgent: string;
	toAgent: string;
	/** Permissions carried by this grant, constraints included. */
	permissions: Permission[];
	depth: number;
	maxDepth: number;
	expiresAt: Date;
	createdAt: Date;
}

/** Who stands behind the acting agent, ordered from the human down to the agent. */
export interface HookDelegationChain {
	/** Human owning the root agent. The accountable principal. Undefined only if the root agent row vanished. */
	rootOwnerId?: string;
	/** Agent ids from the root agent to the acting agent. Length 1 when the agent is not delegated. */
	path: string[];
	/** Grants along `path`, root first. `links[i]` goes from `path[i]` to `path[i + 1]`. Empty when not delegated. */
	links: DelegationLink[];
	/** Every active, unexpired grant whose `toAgent` is the acting agent. authorize() merges all of these, so a hook that wants the full picture reads this, not only `links`. */
	inbound: DelegationLink[];
}

/** Which entry point is asking. */
export type AuthorizeSource = "authorize" | "authorizeByToken" | "policy.evaluate" | "explain";

export interface BeforeAuthorizeContext {
	agentId: string;
	action: string;
	resource: string;
	arguments?: Record<string, unknown>;
	/** The resolved agent (token omitted). */
	agent: Omit<AgentIdentity, "token">;
	/** Chain from the root human to this agent. */
	delegation: HookDelegationChain;
	/** Which entry point is asking. */
	source: AuthorizeSource;
	/** Request metadata (ip, userAgent) when the caller passed it. */
	context?: RequestContext;
	/** True when called from explain(); the hook should not cause side effects. */
	dryRun: boolean;
	/** Aborted when the hook timeout fires. Pass it to fetch(). */
	signal: AbortSignal;
}

/** Legacy shape, still accepted. */
export interface LegacyHookVerdict {
	allow: boolean;
	reason?: string;
}

/** Richer shape, used by external guards. */
export interface HookVerdict {
	decision: "allow" | "deny" | "escalate";
	/** Returned to the calling agent, so it must not contain secrets. */
	reason?: string;
	/** Name of the guard or rule set that decided, written to the audit row. */
	guard?: string;
	ruleId?: string;
	/** Small scalar map, written to the audit row. Max 16 keys, values truncated to 256 chars. */
	metadata?: Record<string, string | number | boolean>;
}

export type BeforeAuthorizeResult = HookVerdict | LegacyHookVerdict | undefined;

export interface TheAuthHooks {
	/**
	 * Fires after the agent is resolved and active, before permissions are evaluated. Runs for authorize(), authorizeByToken() and policy.evaluate() (agent subjects). Return `undefined` or `{ allow: true }` to proceed, `{ allow: false, reason }` or `{ decision: "deny" }` to block, `{ decision: "escalate" }` to require approval. A timeout, a throw or a malformed verdict denies by default, see `hookSafety`.
	 */
	beforeAuthorize?: (context: BeforeAuthorizeContext) => Promise<BeforeAuthorizeResult>;

	/** Fires after authorize() with the final result. */
	afterAuthorize?: (context: {
		agentId: string;
		action: string;
		resource: string;
		source: AuthorizeSource;
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
		source: AuthorizeSource;
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
