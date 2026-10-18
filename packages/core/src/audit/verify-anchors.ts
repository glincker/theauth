/**
 * The records the verifier trusts to explain a gap or a start: erasure records (rows erased on purpose) and anchors (where a chain may begin). None of them is taken at face value. Each must be a chained row whose own hash checks out, and must carry a valid MAC made with the audit key.
 */

import { and, eq, isNotNull } from "drizzle-orm";
import type { Database } from "../db/database.js";
import { auditLogs } from "../db/schema.js";
import type { AuditRow } from "./chain.js";
import { CHECKPOINT_ACTION, computeRowHash, ERASURE_ACTION } from "./chain.js";
import type { AnchorFields, ErasureEntry } from "./integrity.js";
import { anchorMacValid, erasureEntryValid, parseErasureEntry } from "./integrity.js";
import type { ChainAnchor, ChainBreak } from "./verify.js";

export interface ErasureIndex {
	/** Every authenticated entry per erased row id (a row can be erased more than once). */
	byId: Map<string, ErasureEntry[]>;
	/** Authenticated `deleted` entries by `agentId:seq`, for bridging gaps. */
	bySeq: Map<string, ErasureEntry>;
}

function erasureBreak(rec: AuditRow, reason: "erasure_unchained" | "erasure_forged"): ChainBreak {
	return { agentId: rec.agentId, rowId: rec.id, seq: rec.chainSeq ?? 0, reason, rowIds: [rec.id] };
}

/**
 * Collect the authenticated erasure entries. A record that is not on a chain, or that has an entry without a valid MAC, is reported (first one wins) and contributes nothing, so the rows it names show up as the gaps or edits they are. The record's own chain hash is checked by the main walk.
 */
export async function loadErasures(
	db: Database,
	key: string | undefined,
	agentId: string | undefined,
): Promise<{ index: ErasureIndex; brk?: ChainBreak }> {
	const index: ErasureIndex = { byId: new Map(), bySeq: new Map() };
	let brk: ChainBreak | undefined;
	const where = agentId
		? and(eq(auditLogs.action, ERASURE_ACTION), eq(auditLogs.agentId, agentId))
		: eq(auditLogs.action, ERASURE_ACTION);
	const records = await db.select().from(auditLogs).where(where);
	for (const rec of records) {
		if (rec.hash === null || rec.chainSeq === null) {
			brk ??= erasureBreak(rec, "erasure_unchained");
			continue;
		}
		const list = (rec.parameters as { rows?: unknown } | null)?.rows;
		const entries: ErasureEntry[] = [];
		let valid = Array.isArray(list) && key !== undefined;
		for (const item of Array.isArray(list) ? list : []) {
			const entry = parseErasureEntry(item);
			// An entry must also belong to the chain the record sits on.
			if (
				!entry ||
				!key ||
				entry.agentId !== rec.agentId ||
				!(await erasureEntryValid(key, entry))
			) {
				valid = false;
				break;
			}
			entries.push(entry);
		}
		if (!valid) {
			brk ??= erasureBreak(rec, "erasure_forged");
			continue;
		}
		for (const entry of entries) {
			const same = index.byId.get(entry.id) ?? [];
			same.push(entry);
			index.byId.set(entry.id, same);
			if (entry.reason === "deleted") index.bySeq.set(`${entry.agentId}:${entry.seq}`, entry);
		}
	}
	return { index, brk };
}

async function ownHashValid(row: AuditRow, hmacKey: string | undefined): Promise<boolean> {
	if (row.chainSeq === null || row.hash === null) return false;
	return (await computeRowHash(row, row.chainSeq, row.prevHash ?? null, hmacKey)) === row.hash;
}

/**
 * The first row of the walk has no predecessor and is not the genesis row (seq 1). That is allowed only when an authenticated anchor explains it: a retention checkpoint that deleted exactly the rows before it, or an `auth.audit.checkpoint()` anchor naming exactly this row. Anything else is a truncated prefix.
 */
export async function checkPrefixAnchor(
	db: Database,
	first: AuditRow,
	ctx: { hmacKey: string | undefined; macKey: string | undefined },
): Promise<ChainBreak | undefined> {
	const startSeq = first.chainSeq ?? 0;
	const agentId = first.agentId;
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
		const info = (cp.parameters ?? {}) as Record<string, unknown>;
		if (!ctx.macKey || !(await ownHashValid(cp, ctx.hmacKey))) continue;
		if (info.kind === "anchor") {
			const fields: AnchorFields = {
				kind: "anchor",
				agentId,
				firstSeq: Number(info.firstSeq),
				firstId: String(info.firstId),
				firstHash: String(info.firstHash),
			};
			if (fields.firstSeq !== startSeq || fields.firstId !== first.id) continue;
			if (fields.firstHash !== first.hash) continue;
			if (await anchorMacValid(ctx.macKey, fields, info.mac)) return undefined;
			continue;
		}
		if (info.throughSeq !== startSeq - 1 || typeof info.lastHash !== "string") continue;
		const fields: AnchorFields = {
			kind: "retention",
			agentId,
			throughSeq: startSeq - 1,
			lastHash: info.lastHash,
		};
		// Checkpoints written by 1.x carry no MAC. Their chain hash (an HMAC when
		// `audit.hmacKey` is set) is checked above, so they still anchor; a MAC that
		// is present must be valid.
		if (info.mac !== undefined && !(await anchorMacValid(ctx.macKey, fields, info.mac))) continue;
		if ((first.prevHash ?? null) !== info.lastHash) {
			return {
				agentId,
				rowId: first.id,
				seq: startSeq,
				reason: "prev_hash_mismatch",
				rowIds: [cp.id, first.id],
				expected: info.lastHash,
				actual: first.prevHash ?? undefined,
			};
		}
		return undefined;
	}
	return {
		agentId,
		rowId: first.id,
		seq: startSeq,
		reason: "truncated_prefix",
		rowIds: [first.id],
	};
}

/** A caller pinned anchor (for example saved from `checkpoint()` outside the database): the row must still be there with the same id and hash. */
export async function checkPinnedAnchor(
	db: Database,
	anchor: ChainAnchor,
): Promise<ChainBreak | undefined> {
	const rows = await db
		.select({ id: auditLogs.id, hash: auditLogs.hash })
		.from(auditLogs)
		.where(and(eq(auditLogs.agentId, anchor.agentId), eq(auditLogs.chainSeq, anchor.seq)))
		.limit(1);
	const row = rows[0];
	const base = { agentId: anchor.agentId, seq: anchor.seq, expected: anchor.hash };
	if (!row) return { ...base, rowId: "", reason: "truncated_prefix", rowIds: [] };
	if (row.hash !== anchor.hash || (anchor.id !== undefined && row.id !== anchor.id)) {
		return {
			...base,
			rowId: row.id,
			reason: "anchor_mismatch",
			rowIds: [row.id],
			actual: row.hash ?? undefined,
		};
	}
	return undefined;
}
