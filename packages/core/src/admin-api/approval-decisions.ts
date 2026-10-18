import { and, desc, eq, gt } from "drizzle-orm";
import { approverEvidence } from "../approval/approval.js";
import {
	ApprovalQuorumError,
	castApproval,
	listApprovers,
	requiredApprovalsOf,
} from "../approval/quorum.js";
import { recordAuditEvent } from "../audit/record.js";
import { claimCount } from "../db/claim.js";
import type { Database } from "../db/database.js";
import { approvalRequests } from "../db/schema.js";
import type { AuthAssertion, AuthRequirementResult } from "../session/auth-context.js";
import { evaluateAuthRequirement } from "../session/auth-context.js";
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
	/** Approving needs this acr (RFC 9470). Absent: no step-up rule. */
	requiredAcr?: string;
	/** Approving needs a proving event at most this many seconds old. */
	maxAuthAge?: number;
	/** Distinct approvers needed. 1 is the ordinary single approver flow. */
	requiredApprovals: number;
	/** Approvers counted so far. */
	approvalsReceived: number;
	/** Who approved so far, oldest first. Only present when the request needs more than one. */
	approvers?: string[];
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
	return Promise.all(
		rows.map(async (r) => {
			const summary = summarize(r.arguments);
			const required = requiredApprovalsOf(r);
			const approvers = required > 1 ? await listApprovers(db, r.id) : undefined;
			return {
				id: r.id,
				action: r.action,
				resource: r.resource,
				requestedBy: r.userId,
				createdAt: r.createdAt.toISOString(),
				expiresAt: r.expiresAt.toISOString(),
				arguments: summary.text,
				argumentsTruncated: summary.truncated,
				...(r.requiredAcr !== null && { requiredAcr: r.requiredAcr }),
				...(r.maxAuthAge !== null && { maxAuthAge: r.maxAuthAge }),
				requiredApprovals: required,
				approvalsReceived: approvers?.length ?? 0,
				...(approvers && { approvers }),
			};
		}),
	);
}

export type DecisionResult =
	| {
			ok: true;
			id: string;
			/** `pending` means the vote counted and the quorum is not complete yet. */
			status: "approved" | "denied" | "pending";
			respondedAt: string;
			requiredApprovals: number;
			approvalsReceived: number;
	  }
	| { ok: false; status: 403 | 404 | 409; code: string; message: string }
	/** The approver must authenticate again first. Answer 401 with a `WWW-Authenticate` step-up challenge built from `stepUp`. */
	| {
			ok: false;
			status: 401;
			code: "STEP_UP_REQUIRED";
			message: string;
			stepUp: Exclude<AuthRequirementResult, { ok: true }>;
	  };

export interface DecisionInput {
	id: string;
	decision: "approved" | "denied";
	approverId: string;
	systemAgentId: string;
	allowSelfApproval: boolean;
	/** The approver's session assertion. Needed to approve a request that carries a step-up rule. */
	authContext?: AuthAssertion;
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
	const required = requiredApprovalsOf(row);
	// A quorum request never lets the requester count, whatever allowSelfApproval says.
	if (row.userId === input.approverId && (required > 1 || !input.allowSelfApproval)) {
		return {
			ok: false,
			status: 403,
			code: "SELF_APPROVAL",
			message: "The admin who opened a request cannot decide it",
		};
	}
	const requirement =
		input.decision === "approved" && (row.requiredAcr !== null || row.maxAuthAge !== null)
			? {
					...(row.requiredAcr !== null && { acr: row.requiredAcr }),
					...(row.maxAuthAge !== null && { maxAge: row.maxAuthAge }),
				}
			: null;
	if (requirement) {
		const verdict = evaluateAuthRequirement(
			input.authContext,
			requirement,
			Math.floor(Date.now() / 1000),
		);
		if (!verdict.ok) {
			return {
				ok: false,
				status: 401,
				code: "STEP_UP_REQUIRED",
				message: "This approval needs a stronger or more recent sign-in",
				stepUp: verdict,
			};
		}
	}
	const now = new Date();
	if (input.decision === "approved" && required > 1) return approveQuorum(db, input, row, now);
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
			...(requirement && input.authContext && approverEvidence(input.authContext)),
		},
	});
	return {
		ok: true,
		id: row.id,
		status: input.decision,
		respondedAt: now.toISOString(),
		requiredApprovals: required,
		approvalsReceived: approved ? 1 : 0,
	};
}

type ApprovalRow = typeof approvalRequests.$inferSelect;

/** One approver's approval on a quorum request. Each vote gets its own audit row. */
async function approveQuorum(
	db: Database,
	input: DecisionInput,
	row: ApprovalRow,
	now: Date,
): Promise<DecisionResult> {
	const required = requiredApprovalsOf(row);
	let cast: Awaited<ReturnType<typeof castApproval>>;
	try {
		cast = await castApproval(db, row, {
			approverId: input.approverId,
			now,
			approverAcr: input.authContext?.acr,
		});
	} catch (err) {
		if (err instanceof ApprovalQuorumError) {
			return {
				ok: false,
				status: err.code === "SELF_APPROVAL" ? 403 : 409,
				code: err.code,
				message: err.message,
			};
		}
		throw err;
	}
	if (cast.kind === "lost") {
		return {
			ok: false,
			status: 409,
			code: "APPROVAL_NOT_PENDING",
			message: "Request is no longer pending",
		};
	}
	const done = cast.kind === "approved";
	await recordAuditEvent(db, {
		agentId: input.systemAgentId,
		userId: input.approverId,
		actorId: input.approverId,
		approverId: input.approverId,
		action: "admin_api.approval.approve",
		resource: `approval:${row.id}`,
		result: "allowed",
		parameters: {
			approvalId: row.id,
			approverId: input.approverId,
			requesterId: row.userId,
			action: row.action,
			resource: row.resource,
			approvalsReceived: cast.approvers.length,
			approvalsRequired: required,
			quorumComplete: done,
			...(input.authContext && approverEvidence(input.authContext)),
		},
	});
	return {
		ok: true,
		id: row.id,
		status: done ? "approved" : "pending",
		respondedAt: now.toISOString(),
		requiredApprovals: required,
		approvalsReceived: cast.approvers.length,
	};
}
