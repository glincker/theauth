/**
 * Tamper-evident audit chain.
 * Per agent (rather than per tenant or global) because writers for different agents never contend, a replay is exactly one chain, and the unique index on (agent_id, chain_seq) is enough to stop a fork. If another writer took the same seq first, the unique index rejects the insert and the writer re-reads the head and retries. With `hmacKey`, hashes are HMAC-SHA256, so someone with database write access but not the key cannot recompute a valid chain after editing rows.
 */

import { compareCodeUnits } from "../compare.js";
import { hmacSha256, sha256 } from "../crypto/web-crypto.js";
import type { Database } from "../db/database.js";
import type { auditLogs } from "../db/schema.js";
import type { AuditLogRepo } from "../db/store/index.js";
import { storesFor } from "../db/store/index.js";
import { errorText, StoreConflictError } from "../db/store-conflict.js";
import { eventForAction } from "./events.js";
import { computePseudonyms, resolvePseudonymKey } from "./pseudonym.js";
import type { PseudonymRotation } from "./pseudonym-rotation.js";
import { pseudonymsForWrite } from "./pseudonym-rotation.js";
import { scrubNul } from "./scrub.js";

export type AuditInsert = typeof auditLogs.$inferInsert;
export type AuditRow = typeof auditLogs.$inferSelect;

export interface AuditChainConfig {
	/** Secret for HMAC-SHA256 hashing. Without it hashes are plain SHA-256. */
	hmacKey?: string;
	/** Per-period pseudonym secrets instead of one stable pseudonym per subject. */
	pseudonymRotation?: PseudonymRotation;
}

/** Version stamped on rows this code writes. Rows with a NULL hash_version are version 1. */
const CURRENT_HASH_VERSION = 2;
/** Action name of the anchor row that cleanup writes before deleting a chain prefix. */
export const CHECKPOINT_ACTION = "audit.checkpoint";
/** Action name of the unchained side record that erasure writes for rows it could not preserve. */
export const ERASURE_ACTION = "audit.erasure";
const MAX_APPEND_ATTEMPTS = 30;

const registry = new WeakMap<object, AuditChainConfig>();

/** Turn the chain on for a database handle. Called by createTheAuth when `audit.tamperEvident` is set. */
export function enableAuditChain(db: Database, config: AuditChainConfig = {}): void {
	registry.set(db, config);
}

export function getAuditChainConfig(db: Database): AuditChainConfig | undefined {
	return registry.get(db);
}

/**
 * JSON with sorted keys at every depth, so equal data always serializes equally. BigInt becomes a decimal string. A reference cycle throws a TypeError instead of overflowing the stack; a value shared by two siblings is not a cycle.
 */
export function canonicalJson(value: unknown): string {
	return canonicalInner(value, new WeakSet<object>());
}

function canonicalInner(value: unknown, path: WeakSet<object>): string {
	if (value === null || value === undefined) return "null";
	if (typeof value === "bigint") return JSON.stringify(value.toString());
	if (value instanceof Date) return JSON.stringify(value.toISOString());
	if (typeof value === "object") {
		if (path.has(value)) throw new TypeError("canonicalJson: circular reference");
		path.add(value);
		try {
			if (Array.isArray(value)) return `[${value.map((v) => canonicalInner(v, path)).join(",")}]`;
			const obj = value as Record<string, unknown>;
			const parts: string[] = [];
			for (const key of Object.keys(obj).sort(compareCodeUnits)) {
				if (obj[key] === undefined) continue;
				parts.push(`${JSON.stringify(key)}:${canonicalInner(obj[key], path)}`);
			}
			return `{${parts.join(",")}}`;
		} finally {
			path.delete(value);
		}
	}
	return JSON.stringify(value);
}

/** Row fields covered by the hash in every version, normalized so insert-time and read-back values agree. */
function commonFields(row: AuditInsert | AuditRow): Record<string, unknown> {
	const ts = row.timestamp instanceof Date ? row.timestamp.getTime() : Number(row.timestamp);
	return {
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
		timestamp: ts,
	};
}

/** Version 1 (released): raw agentId and userId. Erasing either breaks the hash. */
function hashedFieldsV1(row: AuditInsert | AuditRow): Record<string, unknown> {
	return { ...commonFields(row), agentId: row.agentId, userId: row.userId };
}

/**
 * Version 2 chains these columns: id, action, resource, parameters, result, reason, durationMs, tokensCost, ip, userAgent, cacheHit, timestamp, policyVersion, delegationChain, inputProvenance, and idPseudonyms (keyed pseudonyms of userId, agentId, subjectId, actorId, approverId). The raw id columns are NOT hashed, so erasure can blank them. The verifier instead checks that any raw id still present matches its pseudonym.
 */
function hashedFieldsV2(row: AuditInsert | AuditRow): Record<string, unknown> {
	return {
		...commonFields(row),
		policyVersion: row.policyVersion ?? null,
		delegationChain: row.delegationChain ?? null,
		inputProvenance: row.inputProvenance ?? null,
		idPseudonyms: row.idPseudonyms ?? null,
	};
}

/** The exact string that is hashed for a row: canonical JSON of `{v, seq, prev, row}`. Exported for conformance vectors and offline verifiers. */
export function chainPayload(
	row: AuditInsert | AuditRow,
	chainSeq: number,
	prevHash: string | null,
): string {
	const version = row.hashVersion ?? 1;
	return canonicalJson({
		v: version,
		seq: chainSeq,
		prev: prevHash,
		row: version >= 2 ? hashedFieldsV2(row) : hashedFieldsV1(row),
	});
}

export async function computeRowHash(
	row: AuditInsert | AuditRow,
	chainSeq: number,
	prevHash: string | null,
	hmacKey?: string,
): Promise<string> {
	const payload = chainPayload(row, chainSeq, prevHash);
	return hmacKey ? hmacSha256(hmacKey, payload) : sha256(payload);
}

let lastRecordedMs = 0;

/**
 * Millisecond write-order stamp for `audit_logs.recorded_at_ms`. Strictly greater than the previous stamp issued by this process and than `floor` (the chain head's stamp), so same-second and same-millisecond writes keep their order even if the clock stalls or another process wrote ahead. Not hashed.
 */
export function nextRecordedAtMs(floor = 0): number {
	lastRecordedMs = Math.max(Date.now(), lastRecordedMs + 1, floor + 1);
	return lastRecordedMs;
}

/** Insert an audit row. Plain insert unless the chain is enabled for this database, in which case the row is linked to its agent's chain. */
export async function insertAuditRow(db: Database, input: AuditInsert): Promise<void> {
	// `event` is stored beside the row and is not hashed.
	const values: AuditInsert = scrubNul({
		...input,
		event: input.event ?? eventForAction(input.action),
	});
	const config = registry.get(db);
	const audit = storesFor(db).audit;
	if (!config) {
		await audit.insertUnchained({
			...values,
			recordedAtMs: values.recordedAtMs ?? nextRecordedAtMs(),
		});
		return;
	}
	// Same-process writers for one agent queue up. The unique index guards against other processes.
	await audit.exclusive(values.agentId, () => appendChained(db, audit, values, config));
}

async function appendChained(
	db: Database,
	audit: AuditLogRepo,
	values: AuditInsert,
	config: AuditChainConfig,
): Promise<void> {
	// Whole seconds, because that is all the SQLite timestamp column keeps.
	// Hashing the truncated value keeps read-back rows verifiable.
	const stamped: AuditInsert = {
		...values,
		hashVersion: CURRENT_HASH_VERSION,
		timestamp: new Date(Math.floor(values.timestamp.getTime() / 1000) * 1000),
	};
	const pseudonymKey = await resolvePseudonymKey(db, config.hmacKey, true);
	if (!pseudonymKey) throw new Error("no audit pseudonym key available");
	stamped.idPseudonyms = config.pseudonymRotation
		? await pseudonymsForWrite(db, stamped, config.pseudonymRotation)
		: await computePseudonyms(stamped, pseudonymKey);
	await linkAndAppend(audit, stamped, config.hmacKey);
}

/**
 * Links a fully stamped row (hash version, whole second timestamp, pseudonyms) to its agent's chain and inserts it, retrying while another writer takes the seq. Runs on a repository alone, so any backend that implements `AuditLogRepo` gets the same algorithm. Call it inside `audit.exclusive`.
 */
export async function linkAndAppend(
	audit: AuditLogRepo,
	stamped: AuditInsert,
	hmacKey: string | undefined,
): Promise<void> {
	let lastError: unknown;
	for (let attempt = 0; attempt < MAX_APPEND_ATTEMPTS; attempt++) {
		const head = await audit.readHead(stamped.agentId);
		const chainSeq = head ? head.seq + 1 : 1;
		const prevHash = head ? head.hash : null;
		const hash = await computeRowHash(stamped, chainSeq, prevHash, hmacKey);
		try {
			await audit.appendAt({
				...stamped,
				chainSeq,
				prevHash,
				hash,
				recordedAtMs: nextRecordedAtMs(head?.recordedAtMs ?? 0),
			});
			return;
		} catch (err) {
			if (!(err instanceof StoreConflictError)) throw err;
			lastError = err.cause;
			// Another process took this seq. Back off a little so racing writers spread out.
			await new Promise((resolve) => setTimeout(resolve, Math.random() * 4 * (attempt + 1)));
		}
	}
	throw new Error(
		`audit chain append gave up after ${MAX_APPEND_ATTEMPTS} attempts: ${errorText(lastError)}`,
	);
}
