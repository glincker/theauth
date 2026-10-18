import { and, eq, gt, isNull } from "drizzle-orm";
import { canonicalJson } from "../audit/chain.js";
import { stripReservedAuditKeys } from "../audit/reserved.js";
import { sha256 } from "../crypto/web-crypto.js";
import type { Database } from "../db/database.js";
import { approvalRequests } from "../db/schema.js";

/** Reason codes returned when an approval cannot be spent. */
export const APPROVAL_CODES = {
	NOT_FOUND: "APPROVAL_NOT_FOUND",
	NOT_APPROVED: "APPROVAL_NOT_APPROVED",
	MISMATCH: "APPROVAL_MISMATCH",
	EXPIRED: "APPROVAL_EXPIRED",
	ALREADY_USED: "APPROVAL_ALREADY_USED",
	/** The arguments presented at spend time differ from the ones the human approved. */
	ARGUMENTS_MISMATCH: "APPROVAL_ARGUMENTS_MISMATCH",
	/** Reason recorded on the allow that spent an approval. */
	CONSUMED: "APPROVAL_CONSUMED",
} as const;

export type ApprovalDenialCode =
	| typeof APPROVAL_CODES.NOT_FOUND
	| typeof APPROVAL_CODES.NOT_APPROVED
	| typeof APPROVAL_CODES.MISMATCH
	| typeof APPROVAL_CODES.EXPIRED
	| typeof APPROVAL_CODES.ALREADY_USED
	| typeof APPROVAL_CODES.ARGUMENTS_MISMATCH;

export interface ConsumeApprovalInput {
	approvalId: string;
	agentId: string;
	action: string;
	resource: string;
	/** The arguments of the call being authorized. Must hash equal to the ones the human approved. Absent means no arguments. */
	arguments?: Record<string, unknown>;
}

/** Canonical hash of what an approver signs off on: the action, the resource and the arguments. Absent arguments and an empty object hash the same. */
export async function hashApprovalAction(
	action: string,
	resource: string,
	args: Record<string, unknown> | null | undefined,
): Promise<string> {
	return sha256(
		canonicalJson({ action, resource, arguments: stripReservedAuditKeys(args ?? undefined) ?? {} }),
	);
}

/** Hash a presented argument bag. Anything that cannot be canonicalized (a cycle) never matches. */
async function safeHash(
	action: string,
	resource: string,
	args: Record<string, unknown> | null | undefined,
): Promise<string | undefined> {
	try {
		return await hashApprovalAction(action, resource, args);
	} catch {
		return undefined;
	}
}

export type ConsumeApprovalResult =
	| { ok: true; approvalId: string; approverId?: string }
	| { ok: false; code: ApprovalDenialCode };

type Row = typeof approvalRequests.$inferSelect;

async function classify(
	row: Row | undefined,
	input: ConsumeApprovalInput,
	now: Date,
): Promise<ApprovalDenialCode | undefined> {
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
	// Bind the spend to the arguments the human saw. A request stored without arguments only
	// covers an argument-less call. Stored arguments are never edited, so this check cannot
	// drift between here and the conditional UPDATE below.
	const approved = await safeHash(row.action, row.resource, row.arguments);
	const presented = await safeHash(input.action, input.resource, input.arguments);
	if (approved === undefined || presented === undefined || approved !== presented) {
		return APPROVAL_CODES.ARGUMENTS_MISMATCH;
	}
	return undefined;
}

async function load(db: Database, id: string): Promise<Row | undefined> {
	const rows = await db.select().from(approvalRequests).where(eq(approvalRequests.id, id)).limit(1);
	return rows[0];
}

/**
 * Verify an approval request and spend it in one step. The request must exist, be approved, belong to the agent, match action and resource exactly, be unexpired and unused. Spending is a single conditional UPDATE that carries every one of those conditions plus `consumed_at IS NULL`, and success means that statement changed a row, so two concurrent callers can never both win. The reads before it only choose the denial code.
 */
export async function consumeApproval(
	db: Database,
	input: ConsumeApprovalInput,
): Promise<ConsumeApprovalResult> {
	const now = new Date();
	const row = await load(db, input.approvalId);
	const early = await classify(row, input, now);
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
		const code = await classify(await load(db, input.approvalId), input, new Date());
		return { ok: false, code: code ?? APPROVAL_CODES.ALREADY_USED };
	}
	return { ok: true, approvalId: input.approvalId, approverId: row?.respondedBy ?? undefined };
}
