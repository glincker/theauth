/**
 * Public types for the unified policy engine.
 *
 * Combines RBAC role expansion, ABAC constraint evaluation, and ReBAC
 * graph queries behind a single evaluate() call. See spec at
 * docs/superpowers/specs/2026-04-16-unified-policy-engine-design.md
 */

export type PolicyEffect = "permit" | "deny" | "indeterminate";

export interface PolicyDecisionSubject {
	agentId?: string;
	userId?: string;
	orgId?: string;
}

export interface PolicyEvaluationContext {
	ip?: string;
	arguments?: Record<string, unknown>;
	timestamp?: Date;
	[key: string]: unknown;
}

export interface EvaluateInput {
	subject: PolicyDecisionSubject;
	action: string;
	resource: string;
	context?: PolicyEvaluationContext;
}

export interface PolicyDecision {
	allowed: boolean;
	effect: PolicyEffect;
	reason: string;
	matchedPermissionId?: string;
	matchedRelation?: string;
	cacheHit: boolean;
	durationMs: number;
	auditId?: string;
}

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
	evaluate(input: EvaluateInput): Promise<PolicyDecision>;
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
}

/**
 * Error codes returned in PolicyDecision.reason when the decision was not
 * a clean PERMIT or DENY from a matched permission.
 */
export const POLICY_ERROR_CODES = {
	INVALID_INPUT: "POLICY_INVALID_INPUT",
	SUBJECT_NOT_FOUND: "POLICY_SUBJECT_NOT_FOUND",
	GRAPH_QUERY_FAILED: "POLICY_GRAPH_QUERY_FAILED",
	AUDIT_WRITE_FAILED: "POLICY_AUDIT_WRITE_FAILED",
	NO_MATCHING_PERMISSION: "POLICY_NO_MATCHING_PERMISSION",
	CONSTRAINT_FAILED: "POLICY_CONSTRAINT_FAILED",
} as const;

export type PolicyErrorCode = (typeof POLICY_ERROR_CODES)[keyof typeof POLICY_ERROR_CODES];
