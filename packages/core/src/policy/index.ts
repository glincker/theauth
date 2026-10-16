// Unified policy engine: RBAC + ABAC + ReBAC behind one evaluate() call.

export { makeDecision, outcomeOf, withEffect } from "./decision.js";
export type { PolicyEngineDeps } from "./engine.js";
export { createPolicyEngine } from "./engine.js";
export { applyRisk, classifyRisk } from "./risk.js";
export { applyTaint, evaluateTaint } from "./taint.js";
export type {
	ApprovalRequirement,
	DecisionPrincipal,
	EscalationInfo,
	EvaluateInput,
	EvaluateOptions,
	InvalidateScope,
	PolicyCacheConfig,
	PolicyCacheStats,
	PolicyCombineStrategy,
	PolicyDecision,
	PolicyDecisionInput,
	PolicyDecisionSubject,
	PolicyEffect,
	PolicyEngine,
	PolicyEngineConfig,
	PolicyErrorCode,
	PolicyEvaluationContext,
	PolicyOutcome,
	RiskCondition,
	RiskConfig,
	RiskContext,
	RiskTierRule,
} from "./types.js";
export { POLICY_ERROR_CODES } from "./types.js";
