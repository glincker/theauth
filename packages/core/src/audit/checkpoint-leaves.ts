/**
 * Turns chained audit rows into Merkle leaves.
 *
 * The log order is (timestamp, id) over every row that has a chain hash, across
 * all agents. A leaf commits to the row id, the row's chain hash and one salted
 * commitment per hashed field. The per-field salt is derived from the audit key
 * and the row hash, so the operator can always rebuild it and never has to store
 * it, while a receipt reveals it only for the fields the caller chooses.
 */

import { and, asc, eq, gt, gte, isNotNull, lte, or } from "drizzle-orm";
import { hmacSha256, sha256 } from "../crypto/web-crypto.js";
import type { Database } from "../db/database.js";
import { auditLogs } from "../db/schema.js";
import type { AuditRow } from "./chain.js";
import { canonicalJson, getAuditChainConfig } from "./chain.js";
import { merkleLeafHash } from "./checkpoint-merkle.js";
import { RECEIPT_FIELDS_V1, RECEIPT_FIELDS_V2 } from "./checkpoint-types.js";
import { resolvePseudonymKey } from "./pseudonym.js";

const ENCODER = new TextEncoder();
const SALT_DOMAIN = "theauth.audit.receipt.salt.v1";
const COMMIT_DOMAIN = "theauth.audit.receipt.field.v1";
const LEAF_VERSION = 1;
const FINGERPRINT_DOMAIN = "theauth.audit.receipt.fp.v1";
/** Rows read per query when building a tree, so memory stays bounded by ids and hashes. */
const LOAD_PAGE = 2000;
/** Most leaf hashes remembered per database. Oldest dropped first. */
const CACHE_MAX_ENTRIES = 100_000;

/** The audit columns a leaf commits to. Everything else on the row is left unread. */
const LEAF_COLUMNS = {
	id: auditLogs.id,
	agentId: auditLogs.agentId,
	userId: auditLogs.userId,
	action: auditLogs.action,
	resource: auditLogs.resource,
	parameters: auditLogs.parameters,
	result: auditLogs.result,
	reason: auditLogs.reason,
	durationMs: auditLogs.durationMs,
	tokensCost: auditLogs.tokensCost,
	ip: auditLogs.ip,
	userAgent: auditLogs.userAgent,
	cacheHit: auditLogs.cacheHit,
	timestamp: auditLogs.timestamp,
	hash: auditLogs.hash,
	hashVersion: auditLogs.hashVersion,
	policyVersion: auditLogs.policyVersion,
	delegationChain: auditLogs.delegationChain,
	inputProvenance: auditLogs.inputProvenance,
	idPseudonyms: auditLogs.idPseudonyms,
};

export type LeafRow = Pick<AuditRow, keyof typeof LEAF_COLUMNS>;

export interface LeafRange {
	since: number | null;
	until: number | null;
}

export interface LogLeaf {
	row: LeafRow;
	rowHash: string;
	fieldValues: Record<string, unknown>;
	/** Hex salt per field. Never leaves the operator except for revealed fields. */
	salts: Record<string, string>;
	commitments: Record<string, string>;
	leafHash: Uint8Array;
}

export function receiptFieldsFor(hashVersion: number): readonly string[] {
	return hashVersion >= 2 ? RECEIPT_FIELDS_V2 : RECEIPT_FIELDS_V1;
}

/** Field values covered by the row hash, normalized the same way the chain does. */
export function fieldValuesOf(row: LeafRow): Record<string, unknown> {
	const version = row.hashVersion ?? 1;
	const timestamp = row.timestamp instanceof Date ? row.timestamp.getTime() : Number(row.timestamp);
	for (const n of [timestamp, row.durationMs, row.tokensCost ?? 0]) {
		if (!Number.isFinite(n)) throw new Error(`audit row ${row.id} has a non-finite number`);
	}
	const values: Record<string, unknown> = {
		id: row.id,
		action: row.action,
		resource: row.resource,
		parameters: row.parameters ?? null,
		result: row.result,
		reason: row.reason ?? null,
		durationMs: row.durationMs,
		tokensCost: row.tokensCost ?? null,
		ip: row.ip ?? null,
		userAgent: row.userAgent ?? null,
		cacheHit: Boolean(row.cacheHit ?? false),
		timestamp,
	};
	if (version >= 2) {
		values.policyVersion = row.policyVersion ?? null;
		values.delegationChain = row.delegationChain ?? null;
		values.inputProvenance = row.inputProvenance ?? null;
		values.idPseudonyms = row.idPseudonyms ?? null;
	} else {
		values.agentId = row.agentId;
		values.userId = row.userId;
	}
	return values;
}

export async function fieldSalt(key: string, rowHash: string, field: string): Promise<string> {
	return hmacSha256(key, `${SALT_DOMAIN}\0${rowHash}\0${field}`);
}

export function fieldCommitment(field: string, salt: string, value: unknown): Promise<string> {
	return sha256(`${COMMIT_DOMAIN}\0${field}\0${salt}\0${canonicalJson(value)}`);
}

/** Canonical leaf bytes. The verifier rebuilds exactly this from a receipt. */
export function leafPreimage(
	rowId: string,
	rowHash: string,
	hashVersion: number,
	commitments: Record<string, string>,
): Uint8Array {
	return ENCODER.encode(
		canonicalJson({ v: LEAF_VERSION, rowId, rowHash, hashVersion, fields: commitments }),
	);
}

export async function resolveReceiptKey(db: Database, hmacKey?: string): Promise<string> {
	const key = await resolvePseudonymKey(db, hmacKey ?? getAuditChainConfig(db)?.hmacKey, true);
	if (!key) throw new Error("no audit key available to derive receipt salts");
	return key;
}

async function buildLeaf(row: LeafRow, key: string): Promise<LogLeaf> {
	const rowHash = row.hash as string;
	const hashVersion = row.hashVersion ?? 1;
	const fieldValues = fieldValuesOf(row);
	const salts: Record<string, string> = {};
	const commitments: Record<string, string> = {};
	for (const field of receiptFieldsFor(hashVersion)) {
		const salt = await fieldSalt(key, rowHash, field);
		salts[field] = salt;
		commitments[field] = await fieldCommitment(field, salt, fieldValues[field]);
	}
	const leafHash = await merkleLeafHash(leafPreimage(row.id, rowHash, hashVersion, commitments));
	return { row, rowHash, fieldValues, salts, commitments, leafHash };
}

/** Build the full leaf (values, salts, commitments) for one row, read by id. Undefined when absent or unchained. */
export async function loadLeaf(
	db: Database,
	rowId: string,
	hmacKey?: string,
): Promise<LogLeaf | undefined> {
	const key = await resolveReceiptKey(db, hmacKey);
	const rows = await db
		.select(LEAF_COLUMNS)
		.from(auditLogs)
		.where(and(eq(auditLogs.id, rowId), isNotNull(auditLogs.hash)))
		.limit(1);
	const row = rows[0];
	return row ? buildLeaf(row, key) : undefined;
}

interface CachedLeaf {
	/** Digest of everything the leaf is computed from, so an edited row never reuses a stale hash. */
	fingerprint: string;
	leafHash: Uint8Array;
}

interface LeafCache {
	key: string;
	entries: Map<string, CachedLeaf>;
}

const caches = new WeakMap<Database, LeafCache>();

function cacheFor(db: Database, key: string): LeafCache {
	let cache = caches.get(db);
	if (!cache || cache.key !== key) {
		cache = { key, entries: new Map() };
		caches.set(db, cache);
	}
	return cache;
}

/**
 * Leaf hash of a row, reused when the row's content is unchanged since the last time it was
 * hashed. The fingerprint costs one digest where a fresh leaf costs about two per field, and
 * it covers every input of the leaf, so a rewritten row is always rehashed and detected.
 */
async function leafHashOf(row: LeafRow, key: string, cache: LeafCache): Promise<Uint8Array> {
	const rowHash = row.hash as string;
	const fingerprint = await sha256(
		`${FINGERPRINT_DOMAIN}\0${row.id}\0${rowHash}\0${row.hashVersion ?? 1}\0${canonicalJson(fieldValuesOf(row))}`,
	);
	const hit = cache.entries.get(row.id);
	if (hit && hit.fingerprint === fingerprint) return hit.leafHash;
	const leaf = await buildLeaf(row, key);
	cache.entries.delete(row.id);
	cache.entries.set(row.id, { fingerprint, leafHash: leaf.leafHash });
	while (cache.entries.size > CACHE_MAX_ENTRIES) {
		const oldest = cache.entries.keys().next().value;
		if (oldest === undefined) break;
		cache.entries.delete(oldest);
	}
	return leaf.leafHash;
}

/** Row ids and leaf hashes of the log, in log order. */
export interface LeafSet {
	ids: string[];
	hashes: Uint8Array[];
}

/**
 * Load the leaf hashes of the log in order, optionally bounded by row timestamp and by a
 * leaf count. Reads only the columns a leaf commits to, a page at a time, with the range,
 * order and limit applied in SQL.
 */
export async function loadLeafSet(
	db: Database,
	range: LeafRange,
	hmacKey?: string,
	limit?: number,
): Promise<LeafSet> {
	const key = await resolveReceiptKey(db, hmacKey);
	const cache = cacheFor(db, key);
	const set: LeafSet = { ids: [], hashes: [] };
	let cursor: { at: Date; id: string } | null = null;
	for (;;) {
		const want = limit === undefined ? LOAD_PAGE : Math.min(LOAD_PAGE, limit - set.ids.length);
		if (want <= 0) return set;
		const conds = [isNotNull(auditLogs.hash)];
		if (range.since !== null) conds.push(gte(auditLogs.timestamp, new Date(range.since)));
		if (range.until !== null) conds.push(lte(auditLogs.timestamp, new Date(range.until)));
		if (cursor) {
			const after = or(
				gt(auditLogs.timestamp, cursor.at),
				and(eq(auditLogs.timestamp, cursor.at), gt(auditLogs.id, cursor.id)),
			);
			if (after) conds.push(after);
		}
		const page: LeafRow[] = await db
			.select(LEAF_COLUMNS)
			.from(auditLogs)
			.where(and(...conds))
			.orderBy(asc(auditLogs.timestamp), asc(auditLogs.id))
			.limit(want);
		for (const row of page) {
			set.ids.push(row.id);
			set.hashes.push(await leafHashOf(row, key, cache));
		}
		const last = page[page.length - 1];
		if (!last || page.length < want) return set;
		cursor = { at: last.timestamp, id: last.id };
	}
}
