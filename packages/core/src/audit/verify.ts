import { and, asc, eq, gte, isNotNull, isNull, lte, ne, sql } from "drizzle-orm";
import type { Database } from "../db/database.js";
import { auditLogs } from "../db/schema.js";
import type { Result } from "../mcp/types.js";
import type { AuditRow } from "./chain.js";
import { CHECKPOINT_ACTION, computeRowHash, ERASURE_ACTION } from "./chain.js";
import {
	isErasedId,
	PSEUDONYM_FIELDS,
	pseudonymMismatches,
	resolvePseudonymKey,
} from "./pseudonym.js";

export interface VerifyAuditChainOptions {
	/** Only check rows with a timestamp at or after this. */
	from?: Date;
	/** Only check rows with a timestamp at or before this. */
	to?: Date;
	/** Limit the check to one agent's chain. */
	agentId?: string;
	/**
	 * A chain head you saved earlier (for example from an export manifest). If the chain is now shorter than this, or has a different hash at that seq, the check reports truncation. Without an anchor, deleting the newest rows of a chain cannot be detected.
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
	| "pseudonym_mismatch"
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
	/** Rows in range with no hash (written before the chain was enabled, or by a writer that skips it). Erasure side records are not counted. */
	unchained: number;
	/**
	 * Rows that were erased on purpose (GDPR) and are accounted for by an `audit.erasure` record: version 1 rows whose ids were rewritten, rows deleted from the middle of a chain, and version 2 rows whose raw ids were blanked. These are reported here, never as tamper.
	 */
	erased: number;
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

/** Walk each agent's chain and report the first broken link. "First" is by agent (in agent id order) and then by seq, so the result is deterministic. */
export async function verifyAuditChain(
	db: Database,
	opts: VerifyAuditChainOptions,
	hmacKey?: string,
): Promise<Result<VerifyAuditChainResult>> {
	try {
		const base = rangeConditions(opts);
		if (opts.agentId) base.push(eq(auditLogs.agentId, opts.agentId));

		const unchainedRows = await db
			.select({ n: sql<number>`count(*)`.mapWith(Number) })
			.from(auditLogs)
			.where(and(isNull(auditLogs.hash), ne(auditLogs.action, ERASURE_ACTION), ...base));
		const unchained = Number(unchainedRows[0]?.n ?? 0);

		const agentRows = await db
			.selectDistinct({ agentId: auditLogs.agentId })
			.from(auditLogs)
			.where(and(isNotNull(auditLogs.chainSeq), ...base))
			.orderBy(asc(auditLogs.agentId));

		let checked = 0;
		let erased = 0;
		let firstBreak: ChainBreak | undefined;
		const heads: ChainHead[] = [];
		const ctx: VerifyContext = {
			hmacKey,
			pseudonymKey: await resolvePseudonymKey(db, hmacKey, false),
			erasures: await loadErasures(db),
		};

		for (const { agentId } of agentRows) {
			const result = await verifyAgentChain(db, agentId, opts, ctx);
			checked += result.checked;
			erased += result.erased;
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
			data: { ok: !firstBreak, checked, unchained, erased, firstBreak, heads },
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
	ctx: VerifyContext,
): Promise<{ checked: number; erased: number; head?: ChainHead; brk?: ChainBreak }> {
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
	if (startSeq === null || startSeq === undefined) return { checked: 0, erased: 0 };

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
		if (!prev) {
			// Predecessor was removed by retention cleanup. If a checkpoint row
			// covers exactly that gap, the first remaining row must link to it.
			const brk = await checkCheckpointLink(db, agentId, startSeq, ctx.hmacKey);
			if (brk) return { checked: 0, erased: 0, brk };
		}
	}

	let checked = 0;
	let erased = 0;
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
			const res = await checkRow(row, prev, ctx);
			checked++;
			erased += res.erased;
			if (res.brk) return { checked, erased, head, brk: res.brk };
			prev = row;
			if (row.chainSeq !== null && row.hash !== null) {
				head = { agentId, seq: row.chainSeq, hash: row.hash };
			}
		}
		cursor += PAGE;
	}
	return { checked, erased, head };
}

/**
 * Checkpoint rows are ordinary chained rows, so their own hash is checked in the main walk. This only compares the recorded last-deleted hash against the first surviving row. Chains cleaned before checkpoints existed have none and are accepted as before.
 */
async function checkCheckpointLink(
	db: Database,
	agentId: string,
	startSeq: number,
	hmacKey: string | undefined,
): Promise<ChainBreak | undefined> {
	const cps = await db
		.select()
		.from(auditLogs)
		.where(
			and(
				eq(auditLogs.agentId, agentId),
				eq(auditLogs.action, CHECKPOINT_ACTION),
				isNotNull(auditLogs.chainSeq),
			),
		);
	for (const cp of cps) {
		const info = cp.parameters as { throughSeq?: unknown; lastHash?: unknown } | null;
		if (!info || info.throughSeq !== startSeq - 1) continue;
		// A forged checkpoint must not be able to bless a bad link.
		if (cp.chainSeq === null || cp.hash === null) continue;
		const own = await computeRowHash(cp, cp.chainSeq, cp.prevHash ?? null, hmacKey);
		if (own !== cp.hash) continue;
		const first = await db
			.select()
			.from(auditLogs)
			.where(and(eq(auditLogs.agentId, agentId), eq(auditLogs.chainSeq, startSeq)))
			.limit(1);
		const row = first[0];
		if (row && (row.prevHash ?? null) !== info.lastHash) {
			return {
				agentId,
				rowId: row.id,
				seq: startSeq,
				reason: "prev_hash_mismatch",
				rowIds: [cp.id, row.id],
				expected: typeof info.lastHash === "string" ? info.lastHash : undefined,
				actual: row.prevHash ?? undefined,
			};
		}
		return undefined;
	}
	return undefined;
}

interface ErasedRow {
	id: string;
	agentId: string;
	seq: number;
	hash: string;
	prevHash: string | null;
}

interface VerifyContext {
	hmacKey: string | undefined;
	/** Key the id pseudonyms are checked with; undefined when none exists yet. */
	pseudonymKey: string | undefined;
	erasures: { byId: Map<string, ErasedRow>; bySeq: Map<string, ErasedRow> };
}

/** Collect the rows that `audit.erasure` side records say were erased on purpose. */
async function loadErasures(db: Database): Promise<VerifyContext["erasures"]> {
	const byId = new Map<string, ErasedRow>();
	const bySeq = new Map<string, ErasedRow>();
	const records = await db
		.select({ parameters: auditLogs.parameters })
		.from(auditLogs)
		.where(and(eq(auditLogs.action, ERASURE_ACTION), isNull(auditLogs.hash)));
	for (const rec of records) {
		const list = (rec.parameters as { rows?: unknown } | null)?.rows;
		if (!Array.isArray(list)) continue;
		for (const item of list as Partial<ErasedRow>[]) {
			if (typeof item.id !== "string" || typeof item.hash !== "string") continue;
			if (typeof item.agentId !== "string" || typeof item.seq !== "number") continue;
			const entry: ErasedRow = {
				id: item.id,
				agentId: item.agentId,
				seq: item.seq,
				hash: item.hash,
				prevHash: typeof item.prevHash === "string" ? item.prevHash : null,
			};
			byId.set(entry.id, entry);
			bySeq.set(`${entry.agentId}:${entry.seq}`, entry);
		}
	}
	return { byId, bySeq };
}

/** Rows between prev and row that an erasure record accounts for, if they link prev to row without a gap in the hashes. Undefined means the gap is real. */
function bridgeErased(prev: AuditRow, row: AuditRow, ctx: VerifyContext): number | undefined {
	if (prev.chainSeq === null) return undefined;
	let expectedPrev = prev.hash;
	let count = 0;
	const end = row.chainSeq ?? 0;
	for (let seq = prev.chainSeq + 1; seq < end; seq++) {
		const gone = ctx.erasures.bySeq.get(`${row.agentId}:${seq}`);
		if (!gone || gone.prevHash !== expectedPrev) return undefined;
		expectedPrev = gone.hash;
		count++;
	}
	return (row.prevHash ?? null) === expectedPrev ? count : undefined;
}

function hasErasedIds(row: AuditRow): boolean {
	const pseudonyms = row.idPseudonyms ?? {};
	return PSEUDONYM_FIELDS.some((f) => {
		const raw = row[f];
		return isErasedId(raw) || (!raw && pseudonyms[f] !== undefined);
	});
}

async function checkRow(
	row: AuditRow,
	prev: AuditRow | undefined,
	ctx: VerifyContext,
): Promise<{ brk?: ChainBreak; erased: number }> {
	const seq = row.chainSeq ?? 0;
	const base = { agentId: row.agentId, rowId: row.id, seq };
	let erased = 0;

	if (row.hash === null) {
		return { brk: { ...base, reason: "missing_hash", rowIds: [row.id] }, erased };
	}
	let linked = false;
	if (prev && prev.chainSeq !== null && seq !== prev.chainSeq + 1) {
		const bridged = seq > prev.chainSeq ? bridgeErased(prev, row, ctx) : undefined;
		if (bridged === undefined) {
			return { brk: { ...base, reason: "seq_gap", rowIds: [prev.id, row.id] }, erased };
		}
		erased += bridged;
		linked = true;
	}
	if (!linked && prev && (row.prevHash ?? null) !== prev.hash) {
		return {
			brk: {
				...base,
				reason: "prev_hash_mismatch",
				rowIds: [prev.id, row.id],
				expected: prev.hash ?? undefined,
				actual: row.prevHash ?? undefined,
			},
			erased,
		};
	}
	const expected = await computeRowHash(row, seq, row.prevHash ?? null, ctx.hmacKey);
	if (expected !== row.hash) {
		// Version 1 hashes cover the raw ids, so erasing them cannot preserve the
		// hash. An audit.erasure record naming this row with its stored hash
		// explains the mismatch; anything else is tamper.
		const gone = ctx.erasures.byId.get(row.id);
		if ((row.hashVersion ?? 1) < 2 && gone && gone.hash === row.hash) {
			return { erased: erased + 1 };
		}
		return {
			brk: { ...base, reason: "hash_mismatch", rowIds: [row.id], expected, actual: row.hash },
			erased,
		};
	}
	if ((row.hashVersion ?? 1) >= 2) {
		if (ctx.pseudonymKey && (await pseudonymMismatches(row, ctx.pseudonymKey)).length > 0) {
			return { brk: { ...base, reason: "pseudonym_mismatch", rowIds: [row.id] }, erased };
		}
		if (hasErasedIds(row)) erased++;
	}
	return { erased };
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
