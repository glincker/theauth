import type { ConstraintName } from "../policy/abac.js";

/**
 * Machine-readable outcome of an authorization decision. Set where the decision is made and carried on `AuthorizeResult.code` and `PolicyDecision.code`, so callers branch on a closed set instead of parsing `reason` text.
 */
export const DECISION_CODES = {
	ALLOWED: "allowed",
	APPROVAL_CONSUMED: "approval_consumed",
	NO_PERMISSION: "no_permission",
	RATE_LIMITED: "rate_limited",
	IP_NOT_ALLOWED: "ip_not_allowed",
	TIME_RESTRICTED: "time_restricted",
	ARGUMENT_REJECTED: "argument_rejected",
	APPROVAL_REQUIRED: "approval_required",
	/** Generic fallback. The approval paths now emit one of the specific `approval_*` codes below. */
	APPROVAL_INVALID: "approval_invalid",
	APPROVAL_NOT_FOUND: "approval_not_found",
	APPROVAL_PENDING: "approval_pending",
	APPROVAL_DENIED: "approval_denied",
	APPROVAL_EXPIRED: "approval_expired",
	APPROVAL_ALREADY_USED: "approval_already_used",
	APPROVAL_MISMATCH: "approval_mismatch",
	APPROVAL_ARGUMENTS_MISMATCH: "approval_arguments_mismatch",
	/** Lifecycle only: a human approved a request. Never returned by authorize. */
	APPROVAL_GRANTED: "approval_granted",
	AGENT_NOT_FOUND: "agent_not_found",
	AGENT_REVOKED: "agent_revoked",
	AGENT_EXPIRED: "agent_expired",
	INVALID_TOKEN: "invalid_token",
	OWNER_MISMATCH: "owner_mismatch",
	HOOK_DENIED: "hook_denied",
	HOOK_TIMEOUT: "hook_timeout",
	HOOK_ERROR: "hook_error",
	TAINT_VIOLATION: "taint_violation",
	RISK_ESCALATION: "risk_escalation",
	POLICY_INDETERMINATE: "policy_indeterminate",
} as const;

export type DecisionCode = (typeof DECISION_CODES)[keyof typeof DECISION_CODES];

/** Every code except the ones that mean the call went through or a human said yes. */
export type DenialCode = Exclude<
	DecisionCode,
	"allowed" | "approval_consumed" | "approval_granted"
>;

/** Coarse grouping reported as `onViolation.type`. */
export type ViolationType =
	| "permission_denied"
	| "rate_limited"
	| "ip_blocked"
	| "time_restricted"
	| "approval_required";

const CODE_VALUES: ReadonlySet<string> = new Set(Object.values(DECISION_CODES));

export function isDecisionCode(value: unknown): value is DecisionCode {
	return typeof value === "string" && CODE_VALUES.has(value);
}

/** True for approval_required and every code that explains why an approval could not be spent. */
export function isApprovalDenial(code: DecisionCode | undefined): boolean {
	return code !== undefined && violationTypeOf(code) === "approval_required";
}

/** Map a decision code to the coarse `onViolation.type` grouping. */
export function violationTypeOf(code: DecisionCode): ViolationType {
	switch (code) {
		case "rate_limited":
			return "rate_limited";
		case "ip_not_allowed":
			return "ip_blocked";
		case "time_restricted":
			return "time_restricted";
		case "approval_required":
		case "approval_invalid":
		case "approval_not_found":
		case "approval_pending":
		case "approval_denied":
		case "approval_expired":
		case "approval_already_used":
		case "approval_mismatch":
		case "approval_arguments_mismatch":
			return "approval_required";
		default:
			return "permission_denied";
	}
}

const CONSTRAINT_CODES: Record<ConstraintName, DenialCode> = {
	maxCallsPerHour: "rate_limited",
	allowedArgPatterns: "argument_rejected",
	requireApproval: "approval_required",
	timeWindow: "time_restricted",
	ipAllowlist: "ip_not_allowed",
};

/** Map a constraint name to the code its failure carries. */
export function codeForConstraint(name: ConstraintName): DenialCode {
	return CONSTRAINT_CODES[name];
}
