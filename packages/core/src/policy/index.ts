/**
 * Unified policy engine: RBAC + ABAC + ReBAC behind one evaluate() call.
 * See docs/superpowers/specs/2026-04-16-unified-policy-engine-design.md
 */

export type {
	EvaluateInput,
	InvalidateScope,
	PolicyCacheConfig,
	PolicyCacheStats,
	PolicyCombineStrategy,
	PolicyDecision,
	PolicyDecisionSubject,
	PolicyEffect,
	PolicyEngine,
	PolicyEngineConfig,
	PolicyErrorCode,
	PolicyEvaluationContext,
} from "./types.js";
export { POLICY_ERROR_CODES } from "./types.js";
