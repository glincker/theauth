import { and, asc, eq, gte, isNotNull, isNull, lte, ne, sql } from "drizzle-orm";
import type { Database } from "../db/database.js";
import { auditLogs } from "../db/schema.js";
import type { Result } from "../mcp/types.js";
import type { AuditRow } from "./chain.js";
import { computeRowHash, ERASURE_ACTION } from "./chain.js";
import {
	isErasedId,
	PSEUDONYM_FIELDS,
	pseudonymMismatches,
	resolvePseudonymKey,
} from "./pseudonym.js";
import type { ErasureIndex } from "./verify-anchors.js";
import { checkPinnedAnchor, checkPrefixAnchor, loadErasures } from "./verify-anchors.js";

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
	/**
	 * Chain starts you saved outside the database (for example from `auth.audit.checkpoint()`). Each row must still exist with the same id and hash, so deleting or rewriting the start of a chain is caught even by someone who can also forge database anchors.
	 */
	anchors?: ChainAnchor[];
	/**
	 * Accept a chain whose oldest remaining row is not seq 1 and is not explained by a retention checkpoint or a `checkpoint()` anchor. Off by default, because that is exactly what deleting the oldest rows looks like. For chains cut before anchors existed, prefer calling `checkpoint()` once.
	 */
	allowUnanchoredPrefix?: boolean;
}

/** A row a chain is pinned to start at (or pass through). */
export interface ChainAnchor {
	agentId: string;
	seq: number;
	hash: string;
	/** Row id. Checked when given. */
	id?: string;
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
	| "truncated"
	/** The oldest rows of the chain are gone and no authenticated anchor explains it. */
	| "truncated_prefix"
	/** A caller pinned anchor names a row whose hash or id differs. */
	| "anchor_mismatch"
	/** An `audit.erasure` record is not on a hash chain (hand written, or from a writer without the chain). */
	| "erasure_unchained"
	/** An `audit.erasure` record has an entry with a missing or wrong MAC. */
	| "erasure_forged"
	/** A row carries a lower hash_version than the format it was written in (for example hash_version rewritten to NULL). */
	| "version_downgrade";

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
	 * Rows that were erased on purpose (GDPR) and are accounted for by an authenticated `audit.erasure` record: version 1 rows whose ids were rewritten, rows deleted from the middle of a chain, and version 2 rows whose raw ids were blanked. These are reported here, never as tamper.
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
		const pseudonymKey = await resolvePseudonymKey(db, hmacKey, false);
		const loaded = await loadErasures(db, pseudonymKey, opts.agentId);
		firstBreak = loaded.brk;
		const ctx: VerifyContext = {
			hmacKey,
			pseudonymKey,
			erasures: loaded.index,
			allowUnanchoredPrefix: opts.allowUnanchoredPrefix === true,
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
		for (const anchor of opts.anchors ?? []) {
			if (opts.agentId && anchor.agentId !== opts.agentId) continue;
			const brk = await checkPinnedAnchor(db, anchor);
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
	let prefixErased = 0;
	if (startSeq > 1) {
		const pred = await db
			.select()
			.from(auditLogs)
			.where(and(eq(auditLogs.agentId, agentId), eq(auditLogs.chainSeq, startSeq - 1)))
			.limit(1);
		prev = pred[0];
		if (!prev && !ctx.allowUnanchoredPrefix) {
			const res = await checkStart(db, agentId, startSeq, ctx);
			if (res.brk) return { checked: 0, erased: 0, brk: res.brk };
			prefixErased = res.erased;
		}
	}

	let checked = 0;
	let erased = prefixErased;
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
 * The rows before `startSeq` are gone. Rows deleted by erasure are walked back through their authenticated entries; the walk must end at the genesis row, at a row that is still present, or at an authenticated anchor (retention checkpoint or `checkpoint()`). Otherwise this is a truncated prefix.
 */
async function checkStart(
	db: Database,
	agentId: string,
	startSeq: number,
	ctx: VerifyContext,
): Promise<{ brk?: ChainBreak; erased: number }> {
	const at = (seq: number) =>
		db
			.select()
			.from(auditLogs)
			.where(and(eq(auditLogs.agentId, agentId), eq(auditLogs.chainSeq, seq)))
			.limit(1);
	const firstRow = (await at(startSeq))[0];
	if (!firstRow) return { erased: 0 };
	let seq = startSeq;
	let expectedPrev = firstRow.prevHash ?? null;
	while (seq > 1) {
		const gone = ctx.erasures.bySeq.get(`${agentId}:${seq - 1}`);
		if (!gone || gone.hash !== expectedPrev) break;
		expectedPrev = gone.prevHash;
		seq--;
	}
	const erased = startSeq - seq;
	if (seq === 1 && expectedPrev === null) return { erased };
	if (erased > 0) {
		const before = (await at(seq - 1))[0];
		if (before && before.hash === expectedPrev) return { erased };
	}
	// The anchor must explain the start of the walk (an erased row keeps its seq and link).
	const start = { ...firstRow, chainSeq: seq, prevHash: expectedPrev };
	const brk = await checkPrefixAnchor(db, start, {
		hmacKey: ctx.hmacKey,
		macKey: ctx.pseudonymKey,
	});
	return brk ? { brk: { ...brk, rowId: firstRow.id, seq: startSeq }, erased: 0 } : { erased };
}

interface VerifyContext {
	hmacKey: string | undefined;
	/** Key the id pseudonyms, erasure entries and anchors are checked with; undefined when none exists yet. */
	pseudonymKey: string | undefined;
	erasures: ErasureIndex;
	allowUnanchoredPrefix: boolean;
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
	// Version 1 writers never stored pseudonyms, and a chain never steps back to
	// an older format. Either sign means hash_version was rewritten.
	const version = row.hashVersion ?? 1;
	if (version < 2 && (row.idPseudonyms != null || (prev && (prev.hashVersion ?? 1) >= 2))) {
		return { brk: { ...base, reason: "version_downgrade", rowIds: [row.id] }, erased };
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
		// hash. An authenticated erasure entry naming this row with its stored hash,
		// and with the hash of the row as erasure left it, explains the mismatch.
		// Anything else is tamper.
		const entries = ctx.erasures.byId.get(row.id) ?? [];
		const excused = entries.some(
			(e) =>
				version < 2 &&
				e.hashVersion < 2 &&
				e.reason === "anonymized" &&
				e.seq === seq &&
				e.hash === row.hash &&
				e.erasedHash === expected,
		);
		if (excused) return { erased: erased + 1 };
		return {
			brk: { ...base, reason: "hash_mismatch", rowIds: [row.id], expected, actual: row.hash },
			erased,
		};
	}
	if ((row.hashVersion ?? 1) >= 2) {
		if (ctx.pseudonymKey && (await pseudonymMismatches(row, ctx.pseudonymKey)).length > 0) {
			return { brk: { ...base, reason: "pseudonym_mismatch", rowIds: [row.id] }, erased };
		}
		// An erasure record carries placeholder ids by design; it is not itself erased.
		if (row.action !== ERASURE_ACTION && hasErasedIds(row)) erased++;
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
