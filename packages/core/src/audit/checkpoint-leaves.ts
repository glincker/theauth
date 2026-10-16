/**
 * Turns chained audit rows into Merkle leaves.
 *
 * The log order is (timestamp, id) over every row that has a chain hash, across
 * all agents. A leaf commits to the row id, the row's chain hash and one salted
 * commitment per hashed field. The per-field salt is derived from the audit key
 * and the row hash, so the operator can always rebuild it and never has to store
 * it, while a receipt reveals it only for the fields the caller chooses.
 */

import { and, asc, gte, isNotNull, lte } from "drizzle-orm";
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

export interface LeafRange {
	since: number | null;
	until: number | null;
}

export interface LogLeaf {
	row: AuditRow;
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
export function fieldValuesOf(row: AuditRow): Record<string, unknown> {
	const version = row.hashVersion ?? 1;
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
		timestamp: row.timestamp instanceof Date ? row.timestamp.getTime() : Number(row.timestamp),
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

async function buildLeaf(row: AuditRow, key: string): Promise<LogLeaf> {
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

/** Load the leaves of the log in order, optionally bounded by row timestamp. */
export async function loadLeaves(
	db: Database,
	range: LeafRange,
	hmacKey?: string,
	limit?: number,
): Promise<LogLeaf[]> {
	const key = await resolveReceiptKey(db, hmacKey);
	const conds = [isNotNull(auditLogs.hash)];
	if (range.since !== null) conds.push(gte(auditLogs.timestamp, new Date(range.since)));
	if (range.until !== null) conds.push(lte(auditLogs.timestamp, new Date(range.until)));
	const rows = await db
		.select()
		.from(auditLogs)
		.where(and(...conds))
		.orderBy(asc(auditLogs.timestamp), asc(auditLogs.id));
	const slice = limit === undefined ? rows : rows.slice(0, limit);
	const leaves: LogLeaf[] = [];
	for (const row of slice) leaves.push(await buildLeaf(row, key));
	return leaves;
}
