import { and, asc, eq, gt } from "drizzle-orm";
import { claimCount } from "../db/claim.js";
import type { Database } from "../db/database.js";
import { approvalRequests, approvalVotes } from "../db/schema.js";
import { toStoreConflict } from "../db/store-conflict.js";

/** Upper bound on `requiredApprovals`. A larger quorum is almost always a typo. */
export const MAX_REQUIRED_APPROVALS = 10;

/** Why a quorum decision was refused before or while it was counted. */
export type ApprovalQuorumErrorCode = "SELF_APPROVAL" | "DUPLICATE_APPROVER" | "APPROVER_REQUIRED";

/** Thrown when a quorum approval breaks the distinct approver rule. */
export class ApprovalQuorumError extends Error {
	readonly code: ApprovalQuorumErrorCode;
	constructor(code: ApprovalQuorumErrorCode, message: string) {
		super(message);
		this.name = "ApprovalQuorumError";
		this.code = code;
	}
}

type Row = typeof approvalRequests.$inferSelect;

/** A request written before the quorum migration has no value and needs one approver. */
export function requiredApprovalsOf(row: Pick<Row, "requiredApprovals">): number {
	return row.requiredApprovals ?? 1;
}

/** Reject a quorum that is not a whole number between 1 and `MAX_REQUIRED_APPROVALS`. */
export function assertValidQuorum(n: number): void {
	if (!Number.isInteger(n) || n < 1 || n > MAX_REQUIRED_APPROVALS) {
		throw new Error(`requiredApprovals must be an integer from 1 to ${MAX_REQUIRED_APPROVALS}`);
	}
}

/** Approvers counted so far, oldest first. */
export async function listApprovers(db: Database, approvalId: string): Promise<string[]> {
	const rows = await db
		.select({ approverId: approvalVotes.approverId })
		.from(approvalVotes)
		.where(eq(approvalVotes.approvalId, approvalId))
		.orderBy(asc(approvalVotes.decidedAt), asc(approvalVotes.approverId));
	return rows.map((r) => r.approverId);
}

export type CastResult =
	/** The vote counted and the quorum is not complete yet. */
	| { kind: "pending"; approvers: string[] }
	/** The vote completed the quorum and the request is now approved. */
	| { kind: "approved"; approvers: string[] }
	/** The request was decided or expired while the vote was being counted. The vote was withdrawn. */
	| { kind: "lost" };

async function withdraw(db: Database, approvalId: string, approverId: string): Promise<void> {
	await db
		.delete(approvalVotes)
		.where(and(eq(approvalVotes.approvalId, approvalId), eq(approvalVotes.approverId, approverId)));
}

/**
 * Count one approver's approval on a quorum request (`requiredApprovals` above 1). The approver must differ from the requester and from every approver already counted. A duplicate is stopped by the primary key of `theauth_approval_votes`, so two concurrent decisions by one approver cannot both count. The request flips to `approved` with one conditional UPDATE on `status = pending AND expires_at > now`, so expiry covers the whole quorum and only one caller completes it.
 */
export async function castApproval(
	db: Database,
	row: Row,
	input: { approverId: string; now: Date; approverAcr?: string },
): Promise<CastResult> {
	const required = requiredApprovalsOf(row);
	const { approverId, now } = input;
	if (approverId === row.userId || approverId === row.agentId) {
		throw new ApprovalQuorumError(
			"SELF_APPROVAL",
			"The requester cannot approve a request that needs a quorum",
		);
	}
	const duplicate = new ApprovalQuorumError(
		"DUPLICATE_APPROVER",
		"This approver already approved the request",
	);
	if ((await listApprovers(db, row.id)).includes(approverId)) throw duplicate;
	try {
		await db.insert(approvalVotes).values({
			approvalId: row.id,
			approverId,
			decidedAt: now.getTime(),
			approverAcr: input.approverAcr ?? null,
		});
	} catch (err) {
		if (toStoreConflict(err, "approval_votes")) throw duplicate;
		throw err;
	}

	const approvers = await listApprovers(db, row.id);
	if (approvers.length < required) {
		const [fresh] = await db
			.select({ status: approvalRequests.status, expiresAt: approvalRequests.expiresAt })
			.from(approvalRequests)
			.where(eq(approvalRequests.id, row.id))
			.limit(1);
		if (fresh?.status !== "pending" || fresh.expiresAt <= now) {
			await withdraw(db, row.id, approverId);
			return { kind: "lost" };
		}
		return { kind: "pending", approvers };
	}

	const changed = await claimCount(
		db
			.update(approvalRequests)
			.set({ status: "approved", respondedAt: now, respondedBy: approverId })
			.where(
				and(
					eq(approvalRequests.id, row.id),
					eq(approvalRequests.status, "pending"),
					gt(approvalRequests.expiresAt, now),
				),
			),
		{ id: approvalRequests.id },
	);
	if (changed === 1) return { kind: "approved", approvers };

	// Someone else completed or denied it first. The vote is real only if the request is approved
	// and this approver is among the first `required` counted.
	const [after] = await db
		.select({ status: approvalRequests.status })
		.from(approvalRequests)
		.where(eq(approvalRequests.id, row.id))
		.limit(1);
	if (after?.status === "approved" && approvers.slice(0, required).includes(approverId)) {
		return { kind: "approved", approvers: approvers.slice(0, required) };
	}
	await withdraw(db, row.id, approverId);
	return { kind: "lost" };
}
