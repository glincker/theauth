import { and, eq, gt, isNull } from "drizzle-orm";
import type { Database } from "../db/database.js";
import { approvalRequests } from "../db/schema.js";

/** Reason codes returned when an approval cannot be spent. */
export const APPROVAL_CODES = {
	NOT_FOUND: "APPROVAL_NOT_FOUND",
	NOT_APPROVED: "APPROVAL_NOT_APPROVED",
	MISMATCH: "APPROVAL_MISMATCH",
	EXPIRED: "APPROVAL_EXPIRED",
	ALREADY_USED: "APPROVAL_ALREADY_USED",
	/** Reason recorded on the allow that spent an approval. */
	CONSUMED: "APPROVAL_CONSUMED",
} as const;

export type ApprovalDenialCode =
	| typeof APPROVAL_CODES.NOT_FOUND
	| typeof APPROVAL_CODES.NOT_APPROVED
	| typeof APPROVAL_CODES.MISMATCH
	| typeof APPROVAL_CODES.EXPIRED
	| typeof APPROVAL_CODES.ALREADY_USED;

export interface ConsumeApprovalInput {
	approvalId: string;
	agentId: string;
	action: string;
	resource: string;
}

export type ConsumeApprovalResult =
	| { ok: true; approvalId: string; approverId?: string }
	| { ok: false; code: ApprovalDenialCode };

type Row = typeof approvalRequests.$inferSelect;

function classify(row: Row | undefined, input: ConsumeApprovalInput, now: Date) {
	if (!row) return APPROVAL_CODES.NOT_FOUND;
	if (
		row.agentId !== input.agentId ||
		row.action !== input.action ||
		row.resource !== input.resource
	) {
		return APPROVAL_CODES.MISMATCH;
	}
	if (row.status === "expired") return APPROVAL_CODES.EXPIRED;
	if (row.status !== "approved") return APPROVAL_CODES.NOT_APPROVED;
	if (row.consumedAt) return APPROVAL_CODES.ALREADY_USED;
	if (row.expiresAt <= now) return APPROVAL_CODES.EXPIRED;
	return undefined;
}

async function load(db: Database, id: string): Promise<Row | undefined> {
	const rows = await db.select().from(approvalRequests).where(eq(approvalRequests.id, id)).limit(1);
	return rows[0];
}

/**
 * Verify an approval request and spend it in one step. The request must exist,
 * be approved, belong to the agent, match action and resource exactly, be
 * unexpired and unused. Spending is a single conditional UPDATE that carries
 * every one of those conditions plus `consumed_at IS NULL`, and success means
 * that statement changed a row, so two concurrent callers can never both win.
 * The reads before it only choose the denial code.
 */
export async function consumeApproval(
	db: Database,
	input: ConsumeApprovalInput,
): Promise<ConsumeApprovalResult> {
	const now = new Date();
	const row = await load(db, input.approvalId);
	const early = classify(row, input, now);
	if (early) return { ok: false, code: early };

	const updated = await db
		.update(approvalRequests)
		.set({ consumedAt: now })
		.where(
			and(
				eq(approvalRequests.id, input.approvalId),
				eq(approvalRequests.status, "approved"),
				eq(approvalRequests.agentId, input.agentId),
				eq(approvalRequests.action, input.action),
				eq(approvalRequests.resource, input.resource),
				gt(approvalRequests.expiresAt, now),
				isNull(approvalRequests.consumedAt),
			),
		)
		.returning({ id: approvalRequests.id });

	if (updated.length === 0) {
		// Lost a race or the row changed under us. Report why, never allow.
		const code = classify(await load(db, input.approvalId), input, new Date());
		return { ok: false, code: code ?? APPROVAL_CODES.ALREADY_USED };
	}
	return { ok: true, approvalId: input.approvalId, approverId: row?.respondedBy ?? undefined };
}
