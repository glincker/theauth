import { Badge } from "./badge.js";

/** Codes the filter offers. Mirrors core's DECISION_CODES; an unknown code still renders, it just is not listed. */
export const DECISION_CODE_OPTIONS = [
	"allowed",
	"approval_consumed",
	"no_permission",
	"rate_limited",
	"ip_not_allowed",
	"time_restricted",
	"argument_rejected",
	"approval_required",
	"approval_invalid",
	"agent_not_found",
	"agent_revoked",
	"agent_expired",
	"invalid_token",
	"owner_mismatch",
	"hook_denied",
	"hook_timeout",
	"hook_error",
	"taint_violation",
	"risk_escalation",
	"policy_indeterminate",
] as const;

type CodeVariant = "green" | "red" | "yellow" | "gray";

const GREEN = new Set(["allowed", "approval_consumed"]);
const YELLOW = new Set([
	"approval_required",
	"risk_escalation",
	"rate_limited",
	"hook_timeout",
	"hook_error",
]);

export function codeVariant(code: string): CodeVariant {
	if (GREEN.has(code)) return "green";
	if (YELLOW.has(code)) return "yellow";
	return "red";
}

/** A decision code as a badge. Rows written before codes existed show a dash. */
export function DecisionCodeBadge({ code }: { code?: string }) {
	if (!code) return <span className="text-xs text-zinc-500">-</span>;
	return (
		<span data-testid="decision-code">
			<Badge variant={codeVariant(code)}>{code}</Badge>
		</span>
	);
}
