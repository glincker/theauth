/**
 * Erasure of personal ids from audit rows (GDPR deleteUser).
 * Version 2 chain rows hash keyed pseudonyms of the ids (see pseudonym.ts), so blanking the raw columns leaves their hashes valid and nothing else is needed. Version 1 rows (released format, hash_version NULL or 1) hash the raw agentId and userId, so rewriting those columns cannot keep the hash. For those rows, and for rows deleted outright, an unchained `audit.erasure` side record names each affected row with its stored hash and link, and the verifier reports them as erased instead of as tamper. Destroying the key is a further option and is not implemented (no key shredding).
 */

import { eq, inArray, sql } from "drizzle-orm";
import { generateId } from "../crypto/web-crypto.js";
import type { Database } from "../db/database.js";
import { auditLogs } from "../db/schema.js";
import { ERASURE_ACTION } from "./chain.js";

export interface EraseAuditOptions {
	userId: string;
	/** Agents owned by the user. */
	agentIds: string[];
	/** Placeholder written into the NOT NULL user_id column when anonymizing. */
	anonUserId: string;
	/** Placeholder for an agent id, written into agent_id when anonymizing. */
	anonAgentId: (agentId: string) => string;
	/** true: keep the rows with ids replaced. false: delete the user's rows. */
	keepRows: boolean;
}

interface ErasedRowRecord {
	id: string;
	agentId: string;
	seq: number;
	hash: string;
	prevHash: string | null;
}

/** Returns the number of audit rows anonymized or deleted. */
export async function eraseAuditIdentity(db: Database, opts: EraseAuditOptions): Promise<number> {
	if (opts.agentIds.length === 0) return 0;
	// The audit FK columns are NOT NULL and reference users and agents, so the
	// placeholders (and the erasure record) only fit with enforcement off. It is
	// switched back on immediately.
	await db.run(sql`PRAGMA foreign_keys = OFF`);
	try {
		return opts.keepRows ? await anonymizeRows(db, opts) : await deleteRows(db, opts);
	} finally {
		await db.run(sql`PRAGMA foreign_keys = ON`);
	}
}

async function anonymizeRows(db: Database, opts: EraseAuditOptions): Promise<number> {
	let affected = 0;
	for (const agentId of opts.agentIds) {
		const rows = await db
			.select({
				id: auditLogs.id,
				seq: auditLogs.chainSeq,
				hash: auditLogs.hash,
				prevHash: auditLogs.prevHash,
				hashVersion: auditLogs.hashVersion,
			})
			.from(auditLogs)
			.where(eq(auditLogs.agentId, agentId));
		if (rows.length === 0) continue;
		const anonAgentId = opts.anonAgentId(agentId);
		// Version 1 chained rows lose their hash validity once agentId or userId change.
		const legacy: ErasedRowRecord[] = [];
		for (const r of rows) {
			if (r.seq !== null && r.hash !== null && (r.hashVersion ?? 1) < 2) {
				legacy.push({
					id: r.id,
					agentId: anonAgentId,
					seq: r.seq,
					hash: r.hash,
					prevHash: r.prevHash,
				});
			}
		}
		await db
			.update(auditLogs)
			.set({ userId: opts.anonUserId, agentId: anonAgentId })
			.where(eq(auditLogs.agentId, agentId));
		affected += rows.length;
		if (legacy.length > 0) {
			await writeErasureRecord(db, anonAgentId, opts.anonUserId, legacy);
		}
	}
	// Accountability ids that point at the erased user or their agents. Version 2
	// hashes cover the pseudonyms, so blanking these keeps the chain valid.
	await db.update(auditLogs).set({ subjectId: null }).where(eq(auditLogs.subjectId, opts.userId));
	await db.update(auditLogs).set({ approverId: null }).where(eq(auditLogs.approverId, opts.userId));
	await db
		.update(auditLogs)
		.set({ actorId: null })
		.where(inArray(auditLogs.actorId, opts.agentIds));
	return affected;
}

async function deleteRows(db: Database, opts: EraseAuditOptions): Promise<number> {
	const rows = await db
		.select({
			id: auditLogs.id,
			agentId: auditLogs.agentId,
			seq: auditLogs.chainSeq,
			hash: auditLogs.hash,
			prevHash: auditLogs.prevHash,
		})
		.from(auditLogs)
		.where(eq(auditLogs.userId, opts.userId));
	if (rows.length === 0) return 0;
	const byAgent = new Map<string, ErasedRowRecord[]>();
	for (const r of rows) {
		if (r.seq === null || r.hash === null) continue;
		const list = byAgent.get(r.agentId) ?? [];
		list.push({ id: r.id, agentId: r.agentId, seq: r.seq, hash: r.hash, prevHash: r.prevHash });
		byAgent.set(r.agentId, list);
	}
	for (const [agentId, list] of byAgent) {
		await writeErasureRecord(db, agentId, opts.anonUserId, list);
	}
	await db.delete(auditLogs).where(eq(auditLogs.userId, opts.userId));
	return rows.length;
}

async function writeErasureRecord(
	db: Database,
	agentId: string,
	anonUserId: string,
	rows: ErasedRowRecord[],
): Promise<void> {
	await db.insert(auditLogs).values({
		id: `era_${generateId()}`,
		agentId,
		userId: anonUserId,
		action: ERASURE_ACTION,
		resource: `audit:${agentId}`,
		parameters: { rows },
		result: "allowed",
		reason: "erasure",
		durationMs: 0,
		timestamp: new Date(),
	});
}
