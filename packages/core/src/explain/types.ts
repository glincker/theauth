import type { DelegationLink, HookDelegationChain } from "../hooks/lifecycle.js";
import type { DecisionCode } from "../permission/codes.js";
import type { ConstraintStep } from "../policy/abac.js";
import type { TraceStep } from "../simulator/types.js";
import type { AgentIdentity, Permission, RequestContext } from "../types.js";

export interface ExplainOptions {
	/** Tool arguments, checked against `allowedArgPatterns`. */
	arguments?: Record<string, unknown>;
	/** Request metadata, `ip` is checked against `ipAllowlist`. */
	context?: RequestContext;
	/** Evaluate time windows at this instant. Defaults to now. */
	at?: Date;
	/** Call beforeAuthorize with `dryRun: true`. Default false, because hooks may call external services. */
	runHooks?: boolean;
	/** Reserved. Only "authorize" is implemented. */
	engine?: "authorize";
}

export interface MatchedGrant {
	source: "own" | "delegation";
	/** Index within the agent's own permissions, or within the flattened permissions of all inbound delegation links. */
	index: number;
	permission: Permission;
	resourceMatch: "exact" | "wildcard:prefix" | "wildcard:all";
	actionMatch: "exact" | "wildcard";
	/** Set when source is "delegation": the grant that carried the rule. */
	link?: DelegationLink;
}

export interface ExplainHook {
	configured: boolean;
	evaluated: boolean;
	outcome?: "allow" | "deny" | "escalate" | "timeout" | "error";
	reason?: string;
	guard?: string;
	ruleId?: string;
	elapsedMs?: number;
}

export interface ExplainAttempt {
	source: "own" | "delegation";
	rulesChecked: number;
	outcome: "allow" | "deny" | "escalate" | "no_match";
	code: DecisionCode;
}

export interface NearMiss {
	source: "own" | "delegation";
	/** Set when source is "delegation". */
	delegationId?: string;
	grant: { resource: string; actions: string[] };
	/** Which dimension failed. A grant that matched both is the matchedGrant, never a near miss. */
	mismatch: Array<"resource" | "action">;
	/** Plain hint, e.g. 'resource "mcp:github:issues" does not cover "mcp:github:create_issue"; "mcp:github:*" would'. */
	hint: string;
	/** 0..1: 0.6 times the ":" segment overlap of the resource, plus 0.4 when the action matched. */
	score: number;
}

export interface ExplainResult {
	decision: "allow" | "deny" | "escalate";
	allowed: boolean;
	code: DecisionCode;
	reason: string;
	agent: {
		id: string;
		name: string;
		ownerId: string;
		status: AgentIdentity["status"];
		expiresAt: Date | null;
	} | null;
	/** Root human to agent. Null when the agent was not found. */
	delegation: HookDelegationChain | null;
	/** The rule that decided, or that came closest (matched but failed a constraint). Absent when no rule matched at all. */
	matchedGrant?: MatchedGrant;
	/** Constraint ("policy rule") checks on the matched grant, in evaluation order. */
	constraints: ConstraintStep[];
	/** Which permission sets were tried, in order, and how each ended. */
	attempts: ExplainAttempt[];
	hook: ExplainHook;
	/** Closest grants that failed on resource or action, best first, at most 3. Empty when `matchedGrant` is set. */
	nearMisses: NearMiss[];
	/** Full step list, same TraceStep type as the simulator, with the "hook" stage. */
	trace: TraceStep[];
	evaluatedAt: Date;
}
