import type { Observability } from "../observability/index.js";
import type { DecisionEvent } from "../observability/types.js";
import { DECISION_CODES } from "../permission/codes.js";
import type { ApprovalRequest } from "./approval.js";

export type ApprovalLifecycleStep = "pending" | "approved" | "denied" | "expired";

const SHAPE: Record<ApprovalLifecycleStep, Pick<DecisionEvent, "allowed" | "decision" | "code">> = {
	pending: { allowed: false, decision: "escalate", code: DECISION_CODES.APPROVAL_PENDING },
	approved: { allowed: true, decision: "allow", code: DECISION_CODES.APPROVAL_GRANTED },
	denied: { allowed: false, decision: "deny", code: DECISION_CODES.APPROVAL_DENIED },
	expired: { allowed: false, decision: "deny", code: DECISION_CODES.APPROVAL_EXPIRED },
};

/** Queue one decision event for an approval lifecycle step. Free when no listener is set. */
export function emitApprovalEvent(
	observability: Observability | undefined,
	request: ApprovalRequest,
	step: ApprovalLifecycleStep,
): void {
	if (!observability?.enabled) return;
	const at = new Date();
	observability.emit(
		(): DecisionEvent => ({
			source: "approval",
			agentId: request.agentId,
			ownerId: request.userId,
			action: request.action,
			resource: request.resource,
			...SHAPE[step],
			durationMs: 0,
			cacheHit: false,
			delegationDepth: 0,
			auditId: "",
			at,
		}),
	);
}
