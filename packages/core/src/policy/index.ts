// Unified policy engine: RBAC + ABAC + ReBAC behind one evaluate() call.

export type { PolicyEngineDeps } from "./engine.js";
export { createPolicyEngine } from "./engine.js";
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
