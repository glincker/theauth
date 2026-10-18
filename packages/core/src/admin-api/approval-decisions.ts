import { and, desc, eq, gt } from "drizzle-orm";
import { recordAuditEvent } from "../audit/record.js";
import { claimCount } from "../db/claim.js";
import type { Database } from "../db/database.js";
import { approvalRequests } from "../db/schema.js";
import { scrub } from "./validate.js";

const MAX_ARGUMENT_CHARS = 2048;

export interface PendingApprovalView {
	id: string;
	action: string;
	resource: string;
	requestedBy: string;
	createdAt: string;
	expiresAt: string;
	/** JSON text of the arguments with secret-looking keys redacted, cut at 2 KB. */
	arguments: string;
	argumentsTruncated: boolean;
}

function summarize(args: Record<string, unknown> | null): {
	text: string;
	truncated: boolean;
} {
	const text = JSON.stringify(scrub(args ?? {}));
	return text.length > MAX_ARGUMENT_CHARS
		? { text: text.slice(0, MAX_ARGUMENT_CHARS), truncated: true }
		: { text, truncated: false };
}

/** Pending, unexpired approval requests, newest first. */
export async function listPendingApprovals(
	db: Database,
	max: number,
): Promise<PendingApprovalView[]> {
	const rows = await db
		.select()
		.from(approvalRequests)
		.where(and(eq(approvalRequests.status, "pending"), gt(approvalRequests.expiresAt, new Date())))
		.orderBy(desc(approvalRequests.createdAt))
		.limit(max);
	return rows.map((r) => {
		const summary = summarize(r.arguments);
		return {
			id: r.id,
			action: r.action,
			resource: r.resource,
			requestedBy: r.userId,
			createdAt: r.createdAt.toISOString(),
			expiresAt: r.expiresAt.toISOString(),
			arguments: summary.text,
			argumentsTruncated: summary.truncated,
		};
	});
}

export type DecisionResult =
	| { ok: true; id: string; status: "approved" | "denied"; respondedAt: string }
	| { ok: false; status: 403 | 404 | 409; code: string; message: string };

export interface DecisionInput {
	id: string;
	decision: "approved" | "denied";
	approverId: string;
	systemAgentId: string;
	allowSelfApproval: boolean;
}

/**
 * Approve or deny a pending request. The write is one conditional UPDATE on
 * `status = pending AND expires_at > now`, so a double decision or a race
 * changes a row for exactly one caller; the loser gets 409 and no audit row.
 */
export async function decideApproval(db: Database, input: DecisionInput): Promise<DecisionResult> {
	const [row] = await db
		.select()
		.from(approvalRequests)
		.where(eq(approvalRequests.id, input.id))
		.limit(1);
	if (!row) return { ok: false, status: 404, code: "APPROVAL_NOT_FOUND", message: "Not found" };
	if (row.userId === input.approverId && !input.allowSelfApproval) {
		return {
			ok: false,
			status: 403,
			code: "SELF_APPROVAL",
			message: "The admin who opened a request cannot decide it",
		};
	}
	const now = new Date();
	const updated = await claimCount(
		db
			.update(approvalRequests)
			.set({ status: input.decision, respondedAt: now, respondedBy: input.approverId })
			.where(
				and(
					eq(approvalRequests.id, input.id),
					eq(approvalRequests.status, "pending"),
					gt(approvalRequests.expiresAt, now),
				),
			),
		{ id: approvalRequests.id },
	);
	if (updated === 0) {
		return {
			ok: false,
			status: 409,
			code: "APPROVAL_NOT_PENDING",
			message: "Request is no longer pending",
		};
	}
	const approved = input.decision === "approved";
	await recordAuditEvent(db, {
		agentId: input.systemAgentId,
		userId: input.approverId,
		actorId: input.approverId,
		approverId: input.approverId,
		action: approved ? "admin_api.approval.approve" : "admin_api.approval.deny",
		resource: `approval:${row.id}`,
		result: approved ? "allowed" : "denied",
		parameters: {
			approvalId: row.id,
			approverId: input.approverId,
			requesterId: row.userId,
			action: row.action,
			resource: row.resource,
		},
	});
	return { ok: true, id: row.id, status: input.decision, respondedAt: now.toISOString() };
}
