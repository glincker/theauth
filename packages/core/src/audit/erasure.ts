/**
 * Erasure of personal ids from audit rows (GDPR deleteUser).
 * Version 2 chain rows hash keyed pseudonyms of the ids (see pseudonym.ts), so blanking the raw columns leaves their hashes valid and nothing else is needed. Version 1 rows (released format, hash_version NULL or 1) hash the raw agentId and userId, so rewriting those columns cannot keep the hash. For those rows, and for rows deleted outright, an unchained `audit.erasure` side record names each affected row with its stored hash and link, and the verifier reports them as erased instead of as tamper. Destroying the key is a further option and is not implemented (no key shredding).
 */

import { eq, inArray, or } from "drizzle-orm";
import { generateId } from "../crypto/web-crypto.js";
import type { Database } from "../db/database.js";
import { agents, auditLogs, users } from "../db/schema.js";
import { isUniqueViolation } from "../db/unique-violation.js";
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

/**
 * Tombstones. The audit FK columns are NOT NULL and reference users and agents, and the erased user's own row is deleted afterwards. Instead of switching FK enforcement off (a SQLite-only session setting), anonymized rows are repointed to inert placeholder rows keyed by the same stable anonymous id. They are idempotent, banned or revoked, hold no credential and no personal data, and exist only so the FKs stay satisfied on every dialect.
 */
export async function ensureTombstoneUser(db: Database, anonUserId: string): Promise<void> {
	if (await rowExists(db, users, users.id, anonUserId)) return;
	const now = new Date();
	try {
		await db.insert(users).values({
			id: anonUserId,
			// Unique and recognisably synthetic; never a deliverable address.
			email: `tombstone-${anonUserId.replace(/[^A-Za-z0-9-]/g, "")}@erased.invalid`,
			metadata: {},
			banned: 1,
			banReason: "erased",
			createdAt: now,
			updatedAt: now,
		});
	} catch (error) {
		// A concurrent erasure of the same user inserted it first. Anything else is real.
		if (!isUniqueViolation(error) || !(await rowExists(db, users, users.id, anonUserId)))
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
		if (!isUniqueViolation(error) || !(await rowExists(db, agents, agents.id, anonAgentId))) {
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

async function anonymizeRows(db: Database, opts: EraseAuditOptions): Promise<number> {
	// Rows on the user's agents, plus rows the user caused on other agents.
	const match =
		opts.agentIds.length > 0
			? or(inArray(auditLogs.agentId, opts.agentIds), eq(auditLogs.userId, opts.userId))
			: eq(auditLogs.userId, opts.userId);
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
		.where(match);
	let affected = 0;
	if (rows.length > 0) {
		await ensureTombstoneUser(db, opts.anonUserId);
		const owned = new Set(opts.agentIds);
		// Version 1 chained rows lose their hash validity once agentId or userId change.
		const legacy = new Map<string, ErasedRowRecord[]>();
		for (const r of rows) {
			const newAgentId = owned.has(r.agentId) ? opts.anonAgentId(r.agentId) : r.agentId;
			if (r.seq !== null && r.hash !== null && (r.hashVersion ?? 1) < 2) {
				const list = legacy.get(newAgentId) ?? [];
				list.push({
					id: r.id,
					agentId: newAgentId,
					seq: r.seq,
					hash: r.hash,
					prevHash: r.prevHash,
				});
				legacy.set(newAgentId, list);
			}
		}
		const ownedWithRows = new Set(rows.filter((r) => owned.has(r.agentId)).map((r) => r.agentId));
		for (const agentId of ownedWithRows) {
			const anonAgentId = opts.anonAgentId(agentId);
			await ensureTombstoneAgent(db, anonAgentId, opts.anonUserId);
			await db
				.update(auditLogs)
				.set({ userId: opts.anonUserId, agentId: anonAgentId })
				.where(eq(auditLogs.agentId, agentId));
		}
		await db
			.update(auditLogs)
			.set({ userId: opts.anonUserId })
			.where(eq(auditLogs.userId, opts.userId));
		affected = rows.length;
		for (const [agentId, list] of legacy) {
			await writeErasureRecord(db, agentId, opts.anonUserId, list);
		}
	}
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
	await ensureTombstoneUser(db, opts.anonUserId);
	const owned = new Set(opts.agentIds);
	const byAgent = new Map<string, ErasedRowRecord[]>();
	const tombstoneAgents = new Set<string>();
	for (const r of rows) {
		if (r.seq === null || r.hash === null) continue;
		// The user's own agents are deleted afterwards, so their records name the tombstone agent. Other agents survive and keep their real id, which the verifier needs to bridge the gap.
		const recordAgentId = owned.has(r.agentId) ? opts.anonAgentId(r.agentId) : r.agentId;
		if (owned.has(r.agentId)) tombstoneAgents.add(recordAgentId);
		const list = byAgent.get(recordAgentId) ?? [];
		list.push({ id: r.id, agentId: recordAgentId, seq: r.seq, hash: r.hash, prevHash: r.prevHash });
		byAgent.set(recordAgentId, list);
	}
	for (const [agentId, list] of byAgent) {
		if (tombstoneAgents.has(agentId)) await ensureTombstoneAgent(db, agentId, opts.anonUserId);
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
