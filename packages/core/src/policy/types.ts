// Public types for the unified policy engine.

import type { ProvenanceMap, TaintConfig, TaintVerdict } from "../taint/types.js";

export type PolicyEffect = "permit" | "deny" | "indeterminate" | "escalate";

/** Tri-state outcome of a runtime check. "escalate" means the action is not refused but must not run until a human approves (or the actor steps up). `PolicyDecision.allowed` is true only for "allow". */
export type PolicyOutcome = "allow" | "deny" | "escalate";

/** What a risk tier demands before the action may run. */
export type ApprovalRequirement = "none" | "approval" | "step_up";

/** Typed risk attributes of an action, passed as `context.risk`. */
export interface RiskContext {
	/** Monetary or quantity amount of the action. */
	amount?: number;
	currency?: string;
	/** Data classification of what is touched, e.g. "public", "pii", "financial". */
	dataClass?: string;
	/** True when the action cannot be undone. */
	irreversible?: boolean;
	/** Free-form extra attributes, available to callers and audit. */
	extras?: Record<string, unknown>;
}

/** All set fields must hold for the rule to match. */
export interface RiskCondition {
	/** Matches when risk.amount is at least this value. */
	minAmount?: number;
	/** When set, risk.currency must equal this value. */
	currency?: string;
	/** Matches when risk.dataClass is one of these. */
	dataClasses?: string[];
	irreversible?: boolean;
}

export interface RiskTierRule {
	tier: string;
	when: RiskCondition;
	require: ApprovalRequirement;
}

export interface RiskConfig {
	/** Rules evaluated together; the strongest matching requirement wins. */
	tiers: RiskTierRule[];
}

export interface EscalationInfo {
	tier: string;
	requirement: Exclude<ApprovalRequirement, "none">;
	reason: string;
	/** Set when evaluate() was called with openApproval and a request was opened. */
	approvalRequestId?: string;
}

export interface EvaluateOptions {
	/** On escalate, open an approval request through the approval module. */
	openApproval?: boolean;
}

export interface PolicyDecisionSubject {
	agentId?: string;
	userId?: string;
	orgId?: string;
	/** Owner the request claims the agent acts for. When set, evaluate() denies unless it equals the agent's ownerId. */
	ownerId?: string;
}

export interface PolicyEvaluationContext {
	ip?: string;
	risk?: RiskContext;
	arguments?: Record<string, unknown>;
	/** Provenance labels per argument name ("*" for the whole call). Checked against `PolicyEngineConfig.taint` and written to the audit record's input_provenance. */
	provenance?: ProvenanceMap;
	timestamp?: Date;
	[key: string]: unknown;
}

export interface EvaluateInput {
	subject: PolicyDecisionSubject;
	action: string;
	resource: string;
	context?: PolicyEvaluationContext;
	/** Id of an approved approval request. When the decision would escalate for approval, evaluate() spends this request (single use) and allows instead. */
	approvalId?: string;
}

/** Who an evaluated action is attributable to. */
export interface DecisionPrincipal {
	/** The agent that acted. */
	actorId: string;
	/** The accountable human: root of the delegation chain, else the agent's owner. */
	subjectId?: string;
	/** Agent ids from the root delegator to the actor. Single entry when not delegated. */
	delegationChain: string[];
}

export interface PolicyDecision {
	/** True only when decision is "allow". Derived from `effect`. */
	allowed: boolean;
	/** Tri-state outcome: allow, deny or escalate. Derived from `effect` by makeDecision(). */
	decision: PolicyOutcome;
	/** Canonical field. permit maps to allow, escalate to escalate, the rest to deny. */
	effect: PolicyEffect;
	reason: string;
	escalation?: EscalationInfo;
	/** Resolved accountable principal, present for agent subjects. */
	principal?: DecisionPrincipal;
	matchedPermissionId?: string;
	matchedRelation?: string;
	cacheHit: boolean;
	durationMs: number;
	auditId?: string;
	/** Result of the taint rules, present when provenance was supplied or a strict rule matched. */
	taint?: TaintVerdict;
}

/** Input shape for constructing a PolicyDecision by hand. `decision` and `allowed` are optional and recomputed from `effect` by makeDecision(). */
export type PolicyDecisionInput = Omit<PolicyDecision, "decision" | "allowed"> &
	Partial<Pick<PolicyDecision, "decision" | "allowed">>;

export interface PolicyCacheStats {
	hits: number;
	misses: number;
	size: number;
	evictions: number;
}

export interface InvalidateScope {
	agentId?: string;
	userId?: string;
	resource?: string;
}

export interface PolicyEngine {
	evaluate(input: EvaluateInput, options?: EvaluateOptions): Promise<PolicyDecision>;
	invalidate(scope: InvalidateScope): void;
	stats(): PolicyCacheStats;
}

export type PolicyCombineStrategy = "deny-overrides" | "permit-overrides";

export interface PolicyCacheConfig {
	maxEntries?: number;
	ttlMs?: number;
	enabled?: boolean;
}

export interface PolicyEngineConfig {
	cache?: PolicyCacheConfig;
	combineStrategy?: PolicyCombineStrategy;
	audit?: boolean;
	/** Sample rate for audit row writes, 0.0 to 1.0. Defaults to 1.0. */
	auditSampleRate?: number;
	/** Risk tiers applied after permission matching. */
	risk?: RiskConfig;
	/** Taint rules: which provenance labels may flow into which tools. */
	taint?: TaintConfig;
	/** Version label of the active policy set; written to the audit policy_version field. */
	policyVersion?: string;
}

/** Error codes returned in PolicyDecision.reason when the decision was not a clean PERMIT or DENY from a matched permission. */
export const POLICY_ERROR_CODES = {
	INVALID_INPUT: "POLICY_INVALID_INPUT",
	SUBJECT_NOT_FOUND: "POLICY_SUBJECT_NOT_FOUND",
	GRAPH_QUERY_FAILED: "POLICY_GRAPH_QUERY_FAILED",
	AUDIT_WRITE_FAILED: "POLICY_AUDIT_WRITE_FAILED",
	NO_MATCHING_PERMISSION: "POLICY_NO_MATCHING_PERMISSION",
	CONSTRAINT_FAILED: "POLICY_CONSTRAINT_FAILED",
	ESCALATION_REQUIRED: "POLICY_ESCALATION_REQUIRED",
	OWNER_MISMATCH: "POLICY_OWNER_MISMATCH",
	AGENT_INACTIVE: "POLICY_AGENT_INACTIVE",
	AGENT_NOT_FOUND: "POLICY_AGENT_NOT_FOUND",
	TAINT_VIOLATION: "POLICY_TAINT_VIOLATION",
} as const;

export type PolicyErrorCode = (typeof POLICY_ERROR_CODES)[keyof typeof POLICY_ERROR_CODES];
