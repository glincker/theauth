import type { WebhookModule } from "../auth/webhooks.js";
import type { approvalRequests } from "../db/schema.js";
import type { Observability } from "../observability/index.js";
import type { AuthAssertion, AuthRequirement } from "../session/auth-context.js";
import { ACR_ORDER, acrList } from "../session/auth-context.js";
import { requiredApprovalsOf } from "./quorum.js";

export interface ApprovalRequest {
	id: string;
	agentId: string;
	userId: string;
	action: string;
	resource: string;
	arguments?: Record<string, unknown>;
	status: "pending" | "approved" | "denied" | "expired";
	expiresAt: Date;
	respondedAt?: Date;
	respondedBy?: string;
	/** The approver must have reached this `acr` before approving (RFC 9470). Unset: no requirement. */
	requiredAcr?: string;
	/** The approver's proving event must be at most this many seconds old. Unset: no requirement. */
	maxAuthAge?: number;
	/** Distinct approvers needed before the request is approved. 1 is the ordinary single approver flow. */
	requiredApprovals: number;
	/** Approvers counted so far, oldest first. Only set once the request needs more than one. */
	approvers?: string[];
	createdAt: Date;
}

/** What an approver must prove to approve a request. Same shape as `AuthRequirement`. */
export type ApprovalStepUp = AuthRequirement;

/** What the policy knows about a request when it asks for a step-up rule. */
export interface ApprovalStepUpInput {
	agentId: string;
	userId: string;
	action: string;
	resource: string;
	arguments?: Record<string, unknown>;
}

export interface ApprovalConfig {
	/** How long approval requests stay valid (seconds, default: 300 = 5 min) */
	ttl?: number;
	/** Webhook URL to notify when approval is needed */
	webhookUrl?: string;
	/** Custom notification handler */
	onApprovalNeeded?: (request: ApprovalRequest) => Promise<void>;
	/** Step-up rule for every request: the approver must reach this class (for example `ACR.phishingResistant`) and, with `maxAuthAge`, have proven it recently. Overridden by `stepUp` and by the `stepUp` input of `request()`. */
	requireAcr?: string;
	/** Maximum age in seconds of the approver's proving event. */
	maxAuthAge?: number;
	/** Choose the step-up rule per request, for example only for high risk actions. Return null or undefined to fall back to `requireAcr` and `maxAuthAge`. */
	stepUp?: (request: ApprovalStepUpInput) => ApprovalStepUp | null | undefined;
	/** Distinct approvers every request needs (default 1). Overridden by `quorum` and by the `requiredApprovals` input of `request()`. */
	requiredApprovals?: number;
	/** Choose the quorum per request, for example two approvers for dangerous robot commands. Return null or undefined to fall back to `requiredApprovals`. */
	quorum?: (request: ApprovalStepUpInput) => number | null | undefined;
}

export interface ApprovalDeps {
	/** Receives one decision event per lifecycle step (request, approve, deny, expire). */
	observability?: Observability;
	/** Resolved at call time. A new pending request is sent to it as `approval.pending`. */
	webhooks?: () => Pick<WebhookModule, "emit"> | null;
}

export interface DecideInput {
	decision: "approve" | "deny";
	/** Who decided. Written to the request and to the audit row. */
	decidedBy: string;
	/** The approver's session assertion (`session.auth`). Required to approve a request that has a step-up rule. Denying never needs it. */
	authContext?: AuthAssertion;
}

export function rowToApproval(
	row: typeof approvalRequests.$inferSelect,
	approvers?: string[],
): ApprovalRequest {
	const required = requiredApprovalsOf(row);
	return {
		id: row.id,
		agentId: row.agentId,
		userId: row.userId,
		action: row.action,
		resource: row.resource,
		arguments: row.arguments ?? undefined,
		status: row.status,
		expiresAt: row.expiresAt,
		respondedAt: row.respondedAt ?? undefined,
		respondedBy: row.respondedBy ?? undefined,
		requiredAcr: row.requiredAcr ?? undefined,
		maxAuthAge: row.maxAuthAge ?? undefined,
		requiredApprovals: required,
		...(required > 1 && { approvers: approvers ?? [] }),
		createdAt: row.createdAt,
	};
}

/** Check a rule at request time. A typo in an acr would otherwise make the request impossible to approve. */
export function assertValidStepUp(rule: ApprovalStepUp): void {
	const list = acrList(rule.acr);
	for (const value of list) {
		if (!(ACR_ORDER as readonly string[]).includes(value)) {
			throw new Error(`Unknown acr "${value}" in approval step-up rule`);
		}
	}
	if (rule.maxAge !== undefined && (!Number.isInteger(rule.maxAge) || rule.maxAge < 0)) {
		throw new Error("Approval step-up maxAge must be a non-negative integer");
	}
}

/** What the audit row records about how the approver proved themselves. */
export function approverEvidence(auth: AuthAssertion): Record<string, unknown> {
	return {
		...(auth.acr !== undefined && { approverAcr: auth.acr }),
		...(auth.amr !== undefined && { approverAmr: [...auth.amr] }),
		...(auth.authTime !== undefined && { approverAuthTime: auth.authTime }),
	};
}

/** The rule stored on a row, as an `AuthRequirement`. Null when the row has none. */
export function requirementOf(row: {
	requiredAcr: string | null;
	maxAuthAge: number | null;
}): AuthRequirement | null {
	if (row.requiredAcr === null && row.maxAuthAge === null) return null;
	return {
		...(row.requiredAcr !== null && { acr: row.requiredAcr }),
		...(row.maxAuthAge !== null && { maxAge: row.maxAuthAge }),
	};
}

export async function notifyWebhook(url: string, approvalRequest: ApprovalRequest): Promise<void> {
	try {
		await fetch(url, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({
				event: "approval_needed",
				request: {
					...approvalRequest,
					expiresAt: approvalRequest.expiresAt.toISOString(),
					createdAt: approvalRequest.createdAt.toISOString(),
				},
			}),
		});
	} catch {
		// Webhook delivery failures are non-fatal, the request is already persisted.
	}
}
