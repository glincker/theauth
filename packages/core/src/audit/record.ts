import { eq } from "drizzle-orm";
import { generateId } from "../crypto/web-crypto.js";
import type { Database } from "../db/database.js";
import { agents } from "../db/schema.js";
import type { DecisionCode } from "../permission/codes.js";
import type { AuditInsert } from "./chain.js";
import { insertAuditRow } from "./chain.js";

/** Action of the synthetic row written after best-effort audit writes failed. */
export const WRITE_FAILED_ACTION = "audit.write_failed";

export interface RecordedEvent {
	/** Caller-chosen row id, for callers that return it (policy decisions). Generated when omitted. */
	id?: string;
	agentId: string;
	/** Defaults to the owner of the agent. */
	userId?: string;
	action: string;
	resource: string;
	result: "allowed" | "denied" | "rate_limited" | "escalated";
	reason?: string;
	/** Machine-readable outcome. Stored in its own column, not covered by the audit hash. */
	decisionCode?: DecisionCode;
	durationMs?: number;
	parameters?: Record<string, unknown>;
	subjectId?: string;
	actorId?: string;
	policyVersion?: string;
	approverId?: string;
	delegationChain?: string[];
	inputProvenance?: Record<string, unknown>;
	ip?: string;
	userAgent?: string;
	cacheHit?: boolean;
}

export interface AuditWriteError {
	error: unknown;
	event: RecordedEvent;
	/** Failures not yet covered by a written `audit.write_failed` row, this one included. */
	pendingFailures: number;
	/** Failures since this database handle was created. */
	totalFailures: number;
}

export type AuditWriteErrorHandler = (info: AuditWriteError) => void;

interface FailureState {
	pending: number;
	total: number;
	first?: Date;
	last?: Date;
	onError?: AuditWriteErrorHandler;
}

const states = new WeakMap<object, FailureState>();

function stateFor(db: Database): FailureState {
	let st = states.get(db);
	if (!st) {
		st = { pending: 0, total: 0 };
		states.set(db, st);
	}
	return st;
}

/** Install the `audit.onAuditError` callback for a database handle. Called by createTheAuth. */
export function setAuditWriteErrorHandler(
	db: Database,
	handler: AuditWriteErrorHandler | undefined,
): void {
	stateFor(db).onError = handler;
}

/** Best-effort audit writes that failed since this database handle was created. */
export function getAuditWriteFailures(db: Database): number {
	return states.get(db)?.total ?? 0;
}

function noteFailure(db: Database, event: RecordedEvent, error: unknown): void {
	const st = stateFor(db);
	const now = new Date();
	st.pending++;
	st.total++;
	st.first ??= now;
	st.last = now;
	try {
		st.onError?.({
			error,
			event,
			pendingFailures: st.pending,
			totalFailures: st.total,
		});
	} catch {
		// A throwing callback must not turn a best-effort write into a failure.
	}
}

/**
 * After failures, write one `audit.write_failed` row ahead of the next successful event, in the same agent's chain, so the stored log shows that rows are missing and how many. Mirrors the Go `audit.events_dropped` marker. If the marker cannot be written the count is kept for the next write.
 */
async function writeGapMarker(db: Database, agentId: string, userId: string): Promise<void> {
	const st = stateFor(db);
	const missed = st.pending;
	if (missed === 0) return;
	const first = st.first ?? new Date();
	const last = st.last ?? first;
	st.pending = 0;
	st.first = undefined;
	st.last = undefined;
	try {
		await insertAuditRow(db, {
			id: `aud_${generateId()}`,
			agentId,
			userId,
			action: WRITE_FAILED_ACTION,
			resource: `audit:${agentId}`,
			parameters: {
				failed: missed,
				firstFailed: first.toISOString(),
				lastFailed: last.toISOString(),
				failedTotal: st.total,
				markerSynthetic: true,
			},
			result: "allowed",
			reason: "gap",
			durationMs: 0,
			timestamp: new Date(),
		});
	} catch {
		st.pending += missed;
		st.first = first;
		st.last = last;
	}
}

/**
 * Write a non-authorization event (delegation, approval) to the audit table so it joins the agent's hash chain. Best effort: a failure here must not undo the delegation or approval that already happened, so it returns false and never throws. Failures are not silent, though: each one is counted (getAuditWriteFailures), reported to the `audit.onAuditError` callback, and the next successful write is preceded by an `audit.write_failed` gap row.
 */
export async function recordAuditEvent(db: Database, event: RecordedEvent): Promise<boolean> {
	try {
		let userId = event.userId;
		if (!userId) {
			const rows = await db
				.select({ ownerId: agents.ownerId })
				.from(agents)
				.where(eq(agents.id, event.agentId))
				.limit(1);
			userId = rows[0]?.ownerId;
		}
		if (!userId) throw new Error(`no owner found for agent ${event.agentId}`);
		await writeGapMarker(db, event.agentId, userId);
		const row: AuditInsert = {
			id: event.id ?? `aud_${generateId()}`,
			agentId: event.agentId,
			userId,
			action: event.action,
			resource: event.resource,
			parameters: event.parameters ?? {},
			result: event.result,
			reason: event.reason ?? null,
			decisionCode: event.decisionCode ?? null,
			durationMs: event.durationMs ?? 0,
			timestamp: new Date(),
			subjectId: event.subjectId ?? null,
			actorId: event.actorId ?? null,
			policyVersion: event.policyVersion ?? null,
			approverId: event.approverId ?? null,
			delegationChain: event.delegationChain ?? null,
			inputProvenance: event.inputProvenance ?? null,
			ip: event.ip ?? null,
			userAgent: event.userAgent ?? null,
			cacheHit: event.cacheHit ?? false,
		};
		await insertAuditRow(db, row);
		return true;
	} catch (error) {
		noteFailure(db, event, error);
		return false;
	}
}
