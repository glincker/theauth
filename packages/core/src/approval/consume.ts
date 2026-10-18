import { and, eq, gt, isNull } from "drizzle-orm";
import { canonicalJson } from "../audit/chain.js";
import { stripReservedAuditKeys } from "../audit/reserved.js";
import { sha256 } from "../crypto/web-crypto.js";
import { claimCount } from "../db/claim.js";
import type { Database } from "../db/database.js";
import { approvalRequests } from "../db/schema.js";
import type { DenialCode } from "../permission/codes.js";
import { DECISION_CODES } from "../permission/codes.js";
import type { AuthRequirement } from "../session/auth-context.js";
import { ACR_ORDER, acrList } from "../session/auth-context.js";

/** Reason codes returned when an approval cannot be spent. */
export const APPROVAL_CODES = {
	NOT_FOUND: "APPROVAL_NOT_FOUND",
	/** The request is still waiting for a human. */
	PENDING: "APPROVAL_PENDING",
	/** A human denied the request. */
	DENIED: "APPROVAL_DENIED",
	MISMATCH: "APPROVAL_MISMATCH",
	EXPIRED: "APPROVAL_EXPIRED",
	ALREADY_USED: "APPROVAL_ALREADY_USED",
	/** The arguments presented at spend time differ from the ones the human approved. */
	ARGUMENTS_MISMATCH: "APPROVAL_ARGUMENTS_MISMATCH",
	/** The approval was granted under a weaker step-up rule than the policy demands. */
	STEP_UP_INSUFFICIENT: "APPROVAL_STEP_UP_INSUFFICIENT",
	/** Reason recorded on the allow that spent an approval. */
	CONSUMED: "APPROVAL_CONSUMED",
} as const;

export type ApprovalDenialCode =
	| typeof APPROVAL_CODES.NOT_FOUND
	| typeof APPROVAL_CODES.PENDING
	| typeof APPROVAL_CODES.DENIED
	| typeof APPROVAL_CODES.MISMATCH
	| typeof APPROVAL_CODES.EXPIRED
	| typeof APPROVAL_CODES.ALREADY_USED
	| typeof APPROVAL_CODES.ARGUMENTS_MISMATCH
	| typeof APPROVAL_CODES.STEP_UP_INSUFFICIENT;

const DECISION_BY_DENIAL: Record<ApprovalDenialCode, DenialCode> = {
	APPROVAL_NOT_FOUND: DECISION_CODES.APPROVAL_NOT_FOUND,
	APPROVAL_PENDING: DECISION_CODES.APPROVAL_PENDING,
	APPROVAL_DENIED: DECISION_CODES.APPROVAL_DENIED,
	APPROVAL_MISMATCH: DECISION_CODES.APPROVAL_MISMATCH,
	APPROVAL_EXPIRED: DECISION_CODES.APPROVAL_EXPIRED,
	APPROVAL_ALREADY_USED: DECISION_CODES.APPROVAL_ALREADY_USED,
	APPROVAL_ARGUMENTS_MISMATCH: DECISION_CODES.APPROVAL_ARGUMENTS_MISMATCH,
	APPROVAL_STEP_UP_INSUFFICIENT: DECISION_CODES.APPROVAL_STEP_UP_INSUFFICIENT,
};

/** The typed decision code an approval denial reports on `AuthorizeResult.code` and `PolicyDecision.code`. */
export function decisionCodeOfApproval(code: ApprovalDenialCode): DenialCode {
	return DECISION_BY_DENIAL[code];
}

export interface ConsumeApprovalInput {
	approvalId: string;
	agentId: string;
	action: string;
	resource: string;
	/** The arguments of the call being authorized. Must hash equal to the ones the human approved. Absent means no arguments. */
	arguments?: Record<string, unknown>;
	/** The step-up rule the policy demands. The approval must have been granted under a rule at least this strong, so an ordinary approval cannot stand in for a step-up one. */
	minStepUp?: AuthRequirement;
}

/** True when the rule stored on an approval row is at least as strong as `needed`. */
function stepUpCovers(
	row: { requiredAcr: string | null; maxAuthAge: number | null },
	needed: AuthRequirement,
): boolean {
	const wanted = acrList(needed.acr);
	if (wanted.length > 0) {
		const rank = (v: string): number => (ACR_ORDER as readonly string[]).indexOf(v);
		const need = Math.min(...wanted.map(rank).filter((r) => r >= 0));
		const have = Math.min(
			...acrList(row.requiredAcr ?? "")
				.map(rank)
				.filter((r) => r >= 0),
		);
		if (!Number.isFinite(need) || !Number.isFinite(have) || have < need) return false;
	}
	if (needed.maxAge !== undefined) {
		if (row.maxAuthAge === null || row.maxAuthAge > needed.maxAge) return false;
	}
	return true;
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
	if (row.status === "denied") return APPROVAL_CODES.DENIED;
	if (row.status === "expired") return APPROVAL_CODES.EXPIRED;
	// A request nobody answered in time is expired, not pending.
	if (row.status === "pending") {
		return row.expiresAt <= now ? APPROVAL_CODES.EXPIRED : APPROVAL_CODES.PENDING;
	}
	if (row.consumedAt) return APPROVAL_CODES.ALREADY_USED;
	if (row.expiresAt <= now) return APPROVAL_CODES.EXPIRED;
	if (input.minStepUp && !stepUpCovers(row, input.minStepUp)) {
		return APPROVAL_CODES.STEP_UP_INSUFFICIENT;
	}
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

	const updated = await claimCount(
		db
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
			),
		{ id: approvalRequests.id },
	);

	if (updated === 0) {
		// Lost a race or the row changed under us. Report why, never allow.
		const code = await classify(await load(db, input.approvalId), input, new Date());
		return { ok: false, code: code ?? APPROVAL_CODES.ALREADY_USED };
	}
	return { ok: true, approvalId: input.approvalId, approverId: row?.respondedBy ?? undefined };
}
