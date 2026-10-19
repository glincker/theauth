/**
 * Erasure of personal ids from audit rows (GDPR deleteUser).
 * Version 2 chain rows hash keyed pseudonyms of the ids (see pseudonym.ts), so blanking the raw columns leaves their hashes valid and nothing else is needed. Version 1 rows (released format, hash_version NULL or 1) hash the raw agentId and userId, so rewriting those columns cannot keep the hash. For those rows, and for rows deleted outright, an `audit.erasure` record names each affected row with its stored hash and link, and the verifier reports them as erased instead of as tamper. The record is appended to the agent's hash chain like any other row, and every entry carries an HMAC made with the audit key (see integrity.ts), so a record written by hand without the key excuses nothing. Destroying the key is a further option and is not implemented (no key shredding).
 */

import { and, eq, inArray, or } from "drizzle-orm";
import { generateId, hmacSha256 } from "../crypto/web-crypto.js";
import type { Database } from "../db/database.js";
import { agents, auditLogs, users } from "../db/schema.js";
import { toStoreConflict } from "../db/store-conflict.js";
import type { AuditRow } from "./chain.js";
import { computeRowHash, ERASURE_ACTION, getAuditChainConfig, insertAuditRow } from "./chain.js";
import type { UnsignedErasureEntry } from "./integrity.js";
import { signErasureEntry } from "./integrity.js";
import { resolvePseudonymKey } from "./pseudonym.js";

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

/**
 * Tombstones. The audit FK columns are NOT NULL and reference users and agents, and the erased user's own row is deleted afterwards. Instead of switching FK enforcement off (a SQLite-only session setting), anonymized rows are repointed to inert placeholder rows keyed by the same stable anonymous id. They are idempotent, banned or revoked, hold no credential and no personal data, and exist only so the FKs stay satisfied on every dialect.
 */
export async function ensureTombstoneUser(
	db: Database,
	anonUserId: string,
	metadata: Record<string, unknown> = {},
): Promise<void> {
	if (await rowExists(db, users, users.id, anonUserId)) return;
	const now = new Date();
	try {
		await db.insert(users).values({
			id: anonUserId,
			// Unique and recognisably synthetic; never a deliverable address.
			email: `tombstone-${anonUserId.replace(/[^A-Za-z0-9-]/g, "")}@erased.invalid`,
			metadata,
			banned: 1,
			banReason: "erased",
			createdAt: now,
			updatedAt: now,
		});
	} catch (error) {
		// A concurrent erasure of the same user inserted it first. Anything else is real.
		if (!toStoreConflict(error, "users") || !(await rowExists(db, users, users.id, anonUserId)))
			throw error;
	}
}

export async function ensureTombstoneAgent(
	db: Database,
	anonAgentId: string,
	anonUserId: string,
): Promise<void> {
	if (await rowExists(db, agents, agents.id, anonAgentId)) return;
	const now = new Date();
	try {
		await db.insert(agents).values({
			id: anonAgentId,
			ownerId: anonUserId,
			name: "[erased]",
			type: "service",
			status: "revoked",
			// Not a hex digest, so no presented token can ever hash to it.
			tokenHash: `erased:${generateId()}`,
			tokenPrefix: "erased",
			expiresAt: new Date(0),
			metadata: {},
			createdAt: now,
			updatedAt: now,
		});
	} catch (error) {
		if (
			!toStoreConflict(error, "agents") ||
			!(await rowExists(db, agents, agents.id, anonAgentId))
		) {
			throw error;
		}
	}
}

async function rowExists(
	db: Database,
	table: typeof users | typeof agents,
	idColumn: typeof users.id | typeof agents.id,
	id: string,
): Promise<boolean> {
	const rows = await db.select({ id: idColumn }).from(table).where(eq(idColumn, id));
	return rows.length > 0;
}

/** Returns the number of audit rows anonymized or deleted. */
export async function eraseAuditIdentity(db: Database, opts: EraseAuditOptions): Promise<number> {
	return opts.keepRows ? await anonymizeRows(db, opts) : await deleteRows(db, opts);
}

/**
 * Every pass is safe to rerun after a crash at any statement. Order: tombstones, then the per-agent rewrites, then the erasure record derived from the rewritten rows, then the accountability scrub. A rerun finds the rows already rewritten, so the record pass works from the anonymous ids (which are deterministic) and skips rows an existing record already names.
 *
 * The record cannot go before the rewrite: it is a row on the anonymous agent's hash chain, and the rewritten rows keep their original `chain_seq` on that same chain (unique per agent), so a record appended first would take a seq the rewritten rows need.
 */
async function anonymizeRows(db: Database, opts: EraseAuditOptions): Promise<number> {
	// Rows on the user's agents, plus rows the user caused on other agents.
	const match =
		opts.agentIds.length > 0
			? or(inArray(auditLogs.agentId, opts.agentIds), eq(auditLogs.userId, opts.userId))
			: eq(auditLogs.userId, opts.userId);
	const rows: AuditRow[] = await db.select().from(auditLogs).where(match);
	const owned = new Set(opts.agentIds);
	if (rows.length > 0) {
		await ensureTombstoneUser(db, opts.anonUserId);
		const ownedWithRows = new Set(rows.filter((r) => owned.has(r.agentId)).map((r) => r.agentId));
		for (const agentId of ownedWithRows) {
			await ensureTombstoneAgent(db, opts.anonAgentId(agentId), opts.anonUserId);
		}
		for (const agentId of ownedWithRows) {
			await db
				.update(auditLogs)
				.set({ userId: opts.anonUserId, agentId: opts.anonAgentId(agentId) })
				.where(eq(auditLogs.agentId, agentId));
		}
		await db
			.update(auditLogs)
			.set({ userId: opts.anonUserId })
			.where(eq(auditLogs.userId, opts.userId));
	}
	await recordRewrittenLegacyRows(db, opts);
	// Accountability ids that point at the erased user or their agents. Version 2
	// hashes cover the pseudonyms, so blanking these keeps the chain valid.
	await db.update(auditLogs).set({ subjectId: null }).where(eq(auditLogs.subjectId, opts.userId));
	await db.update(auditLogs).set({ approverId: null }).where(eq(auditLogs.approverId, opts.userId));
	if (opts.agentIds.length > 0) {
		await db
			.update(auditLogs)
			.set({ actorId: null })
			.where(inArray(auditLogs.actorId, opts.agentIds));
	}
	return rows.length;
}

/**
 * Version 1 chained rows lose their hash validity once agentId or userId change. Finds the rows now carrying the placeholder user id whose stored hash no longer matches, and writes the signed record for the ones no record names yet. Reads only the rewritten state, so it works the same on a first pass and on a rerun.
 */
async function recordRewrittenLegacyRows(db: Database, opts: EraseAuditOptions): Promise<void> {
	const rewritten: AuditRow[] = await db
		.select()
		.from(auditLogs)
		.where(eq(auditLogs.userId, opts.anonUserId));
	const legacy = rewritten.filter(
		(r) =>
			r.action !== ERASURE_ACTION &&
			r.chainSeq !== null &&
			r.hash !== null &&
			(r.hashVersion ?? 1) < 2,
	);
	if (legacy.length === 0) return;
	const hmacKey = getAuditChainConfig(db)?.hmacKey;
	const agentIds = [...new Set(legacy.map((r) => r.agentId))];
	const named = await namedByRecords(db, agentIds);
	const byAgent = new Map<string, UnsignedErasureEntry[]>();
	for (const r of legacy) {
		if (named.has(r.id) || r.chainSeq === null || r.hash === null) continue;
		const erasedHash = await computeRowHash(r, r.chainSeq, r.prevHash, hmacKey);
		// A row whose hash still matches was never rewritten, nothing to excuse.
		if (erasedHash === r.hash) continue;
		const list = byAgent.get(r.agentId) ?? [];
		list.push({
			id: r.id,
			agentId: r.agentId,
			seq: r.chainSeq,
			hash: r.hash,
			prevHash: r.prevHash,
			hashVersion: r.hashVersion ?? 1,
			reason: "anonymized",
			erasedHash,
		});
		byAgent.set(r.agentId, list);
	}
	for (const [agentId, list] of byAgent) {
		await writeErasureRecord(db, agentId, opts.anonUserId, list);
	}
}

/** Ids of the audit rows that an existing erasure record on one of these chains already names. */
async function namedByRecords(db: Database, agentIds: string[]): Promise<Set<string>> {
	const records = await db
		.select({ parameters: auditLogs.parameters })
		.from(auditLogs)
		.where(and(eq(auditLogs.action, ERASURE_ACTION), inArray(auditLogs.agentId, agentIds)));
	const ids = new Set<string>();
	for (const rec of records) {
		const list = (rec.parameters as { rows?: unknown } | null)?.rows;
		for (const item of Array.isArray(list) ? list : []) {
			const id = (item as { id?: unknown } | null)?.id;
			if (typeof id === "string") ids.add(id);
		}
	}
	return ids;
}

async function deleteRows(db: Database, opts: EraseAuditOptions): Promise<number> {
	const rows = await db
		.select({
			id: auditLogs.id,
			agentId: auditLogs.agentId,
			seq: auditLogs.chainSeq,
			hash: auditLogs.hash,
			prevHash: auditLogs.prevHash,
			hashVersion: auditLogs.hashVersion,
		})
		.from(auditLogs)
		.where(eq(auditLogs.userId, opts.userId));
	if (rows.length === 0) return 0;
	await ensureTombstoneUser(db, opts.anonUserId);
	const owned = new Set(opts.agentIds);
	const byAgent = new Map<string, UnsignedErasureEntry[]>();
	const tombstoneAgents = new Set<string>();
	for (const r of rows) {
		if (r.seq === null || r.hash === null) continue;
		// The user's own agents are deleted afterwards, so their records name the tombstone agent. Other agents survive and keep their real id, which the verifier needs to bridge the gap.
		const recordAgentId = owned.has(r.agentId) ? opts.anonAgentId(r.agentId) : r.agentId;
		if (owned.has(r.agentId)) tombstoneAgents.add(recordAgentId);
		const list = byAgent.get(recordAgentId) ?? [];
		list.push({
			id: r.id,
			agentId: recordAgentId,
			seq: r.seq,
			hash: r.hash,
			prevHash: r.prevHash,
			hashVersion: r.hashVersion ?? 1,
			reason: "deleted",
			erasedHash: null,
		});
		byAgent.set(recordAgentId, list);
	}
	for (const [agentId, list] of byAgent) {
		if (tombstoneAgents.has(agentId)) await ensureTombstoneAgent(db, agentId, opts.anonUserId);
		await writeErasureRecord(db, agentId, opts.anonUserId, list);
	}
	await db.delete(auditLogs).where(eq(auditLogs.userId, opts.userId));
	return rows.length;
}

/**
 * Sign each entry and append the record to the agent's chain. Written before a hard delete, so a chain whose head is deleted still links to the record. The record id is derived from the agent and the rows it names, so rewriting the same set after a crash, or from two concurrent calls, finds the record already there instead of adding a second one.
 */
async function writeErasureRecord(
	db: Database,
	agentId: string,
	anonUserId: string,
	entries: UnsignedErasureEntry[],
): Promise<void> {
	const key = await resolvePseudonymKey(db, getAuditChainConfig(db)?.hmacKey, true);
	if (!key) throw new Error("no audit key available to sign the erasure record");
	const sorted = [...entries].sort((a, b) => a.id.localeCompare(b.id));
	const id = `era_${(await hmacSha256(key, `theauth.erasure.record.v1:${agentId}:${sorted.map((e) => e.id).join(",")}`)).slice(0, 32)}`;
	if (await auditRowExists(db, id)) return;
	const rows = await Promise.all(sorted.map((e) => signErasureEntry(key, e)));
	try {
		await insertAuditRow(db, {
			id,
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
	} catch (error) {
		// A concurrent erasure wrote the same record first. Anything else is real.
		if (!(await auditRowExists(db, id))) throw error;
	}
}

async function auditRowExists(db: Database, id: string): Promise<boolean> {
	const found = await db.select({ id: auditLogs.id }).from(auditLogs).where(eq(auditLogs.id, id));
	return found.length > 0;
}
