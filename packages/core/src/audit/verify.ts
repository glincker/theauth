import { and, asc, eq, gte, isNotNull, isNull, lte, sql } from "drizzle-orm";
import type { Database } from "../db/database.js";
import { auditLogs } from "../db/schema.js";
import type { Result } from "../mcp/types.js";
import type { AuditRow } from "./chain.js";
import { computeRowHash } from "./chain.js";

export interface VerifyAuditChainOptions {
	/** Only check rows with a timestamp at or after this. */
	from?: Date;
	/** Only check rows with a timestamp at or before this. */
	to?: Date;
	/** Limit the check to one agent's chain. */
	agentId?: string;
	/**
	 * A chain head you saved earlier (for example from an export manifest).
	 * If the chain is now shorter than this, or has a different hash at that
	 * seq, the check reports truncation. Without an anchor, deleting the newest
	 * rows of a chain cannot be detected.
	 */
	expectedHeads?: ChainHead[];
}

export interface ChainHead {
	agentId: string;
	seq: number;
	hash: string;
}

export type ChainBreakReason =
	| "hash_mismatch"
	| "prev_hash_mismatch"
	| "seq_gap"
	| "missing_hash"
	| "truncated";

export interface ChainBreak {
	agentId: string;
	/** The row where the chain first fails. */
	rowId: string;
	seq: number;
	reason: ChainBreakReason;
	/** Row ids involved: the broken row, plus its neighbour for link and gap failures. */
	rowIds: string[];
	expected?: string;
	actual?: string;
}

export interface VerifyAuditChainResult {
	ok: boolean;
	/** Chained rows examined. */
	checked: number;
	/** Rows in range with no hash (written before the chain was enabled, or by a writer that skips it). */
	unchained: number;
	firstBreak?: ChainBreak;
	/** Chain head per agent, as seen at the end of the checked range. */
	heads: ChainHead[];
}

const PAGE = 500;

function rangeConditions(opts: VerifyAuditChainOptions) {
	const c = [];
	if (opts.from) c.push(gte(auditLogs.timestamp, opts.from));
	if (opts.to) c.push(lte(auditLogs.timestamp, opts.to));
	return c;
}

/**
 * Walk each agent's chain and report the first broken link. "First" is by agent
 * (in agent id order) and then by seq, so the result is deterministic.
 */
export async function verifyAuditChain(
	db: Database,
	opts: VerifyAuditChainOptions,
	hmacKey?: string,
): Promise<Result<VerifyAuditChainResult>> {
	try {
		const base = rangeConditions(opts);
		if (opts.agentId) base.push(eq(auditLogs.agentId, opts.agentId));

		const unchainedRows = await db
			.select({ n: sql<number>`count(*)` })
			.from(auditLogs)
			.where(and(isNull(auditLogs.hash), ...base));
		const unchained = Number(unchainedRows[0]?.n ?? 0);

		const agentRows = await db
			.selectDistinct({ agentId: auditLogs.agentId })
			.from(auditLogs)
			.where(and(isNotNull(auditLogs.chainSeq), ...base))
			.orderBy(asc(auditLogs.agentId));

		let checked = 0;
		let firstBreak: ChainBreak | undefined;
		const heads: ChainHead[] = [];

		for (const { agentId } of agentRows) {
			const result = await verifyAgentChain(db, agentId, opts, hmacKey);
			checked += result.checked;
			if (result.head) heads.push(result.head);
			if (result.brk && !firstBreak) firstBreak = result.brk;
		}

		for (const anchor of opts.expectedHeads ?? []) {
			if (opts.agentId && anchor.agentId !== opts.agentId) continue;
			const brk = await checkAnchor(db, anchor);
			if (brk && !firstBreak) firstBreak = brk;
		}

		return {
			success: true,
			data: { ok: !firstBreak, checked, unchained, firstBreak, heads },
		};
	} catch (error) {
		return {
			success: false,
			error: {
				code: "AUDIT_VERIFY_FAILED",
				message: error instanceof Error ? error.message : "Unknown",
			},
		};
	}
}

async function verifyAgentChain(
	db: Database,
	agentId: string,
	opts: VerifyAuditChainOptions,
	hmacKey: string | undefined,
): Promise<{ checked: number; head?: ChainHead; brk?: ChainBreak }> {
	const scope = [eq(auditLogs.agentId, agentId), isNotNull(auditLogs.chainSeq)];
	const range = rangeConditions(opts);

	// Bound the walk by seq rather than timestamp: two writers can stamp
	// rows slightly out of order, and a timestamp filter would then punch
	// holes in the middle of the chain.
	const first = await db
		.select({ seq: auditLogs.chainSeq })
		.from(auditLogs)
		.where(and(...scope, ...range))
		.orderBy(asc(auditLogs.chainSeq))
		.limit(1);
	const startSeq = first[0]?.seq;
	if (startSeq === null || startSeq === undefined) return { checked: 0 };

	const last = await db
		.select({ seq: auditLogs.chainSeq })
		.from(auditLogs)
		.where(and(...scope, ...range))
		.orderBy(sql`${auditLogs.chainSeq} desc`)
		.limit(1);
	const endSeq = last[0]?.seq ?? startSeq;

	let prev: AuditRow | undefined;
	if (startSeq > 1) {
		const pred = await db
			.select()
			.from(auditLogs)
			.where(and(eq(auditLogs.agentId, agentId), eq(auditLogs.chainSeq, startSeq - 1)))
			.limit(1);
		prev = pred[0];
	}

	let checked = 0;
	let cursor = startSeq;
	let head: ChainHead | undefined;
	while (cursor <= endSeq) {
		const page = await db
			.select()
			.from(auditLogs)
			.where(
				and(
					...scope,
					gte(auditLogs.chainSeq, cursor),
					lte(auditLogs.chainSeq, Math.min(endSeq, cursor + PAGE - 1)),
				),
			)
			.orderBy(asc(auditLogs.chainSeq));

		for (const row of page) {
			const brk = await checkRow(row, prev, hmacKey);
			checked++;
			if (brk) return { checked, head, brk };
			prev = row;
			if (row.chainSeq !== null && row.hash !== null) {
				head = { agentId, seq: row.chainSeq, hash: row.hash };
			}
		}
		cursor += PAGE;
	}
	return { checked, head };
}

async function checkRow(
	row: AuditRow,
	prev: AuditRow | undefined,
	hmacKey: string | undefined,
): Promise<ChainBreak | undefined> {
	const seq = row.chainSeq ?? 0;
	const base = { agentId: row.agentId, rowId: row.id, seq };

	if (row.hash === null) {
		return { ...base, reason: "missing_hash", rowIds: [row.id] };
	}
	if (prev && prev.chainSeq !== null && seq !== prev.chainSeq + 1) {
		return { ...base, reason: "seq_gap", rowIds: [prev.id, row.id] };
	}
	if (prev && (row.prevHash ?? null) !== prev.hash) {
		return {
			...base,
			reason: "prev_hash_mismatch",
			rowIds: [prev.id, row.id],
			expected: prev.hash ?? undefined,
			actual: row.prevHash ?? undefined,
		};
	}
	const expected = await computeRowHash(row, seq, row.prevHash ?? null, hmacKey);
	if (expected !== row.hash) {
		return { ...base, reason: "hash_mismatch", rowIds: [row.id], expected, actual: row.hash };
	}
	return undefined;
}

async function checkAnchor(db: Database, anchor: ChainHead): Promise<ChainBreak | undefined> {
	const rows = await db
		.select({ id: auditLogs.id, hash: auditLogs.hash })
		.from(auditLogs)
		.where(and(eq(auditLogs.agentId, anchor.agentId), eq(auditLogs.chainSeq, anchor.seq)))
		.limit(1);
	const row = rows[0];
	if (!row) {
		return {
			agentId: anchor.agentId,
			rowId: "",
			seq: anchor.seq,
			reason: "truncated",
			rowIds: [],
			expected: anchor.hash,
		};
	}
	if (row.hash !== anchor.hash) {
		return {
			agentId: anchor.agentId,
			rowId: row.id,
			seq: anchor.seq,
			reason: "hash_mismatch",
			rowIds: [row.id],
			expected: anchor.hash,
			actual: row.hash ?? undefined,
		};
	}
	return undefined;
}
