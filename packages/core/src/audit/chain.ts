/**
 * Tamper-evident audit chain.
 *
 * Chain scope: one chain per agent. Each agent's rows get chain_seq 1, 2, 3...
 * and every row stores the hash of the previous row (prev_hash) plus its own
 * hash. Per agent (rather than per tenant or global) because writers for
 * different agents never contend, a replay is exactly one chain, and the
 * unique index on (agent_id, chain_seq) is enough to stop a fork.
 *
 * Concurrency: no transaction or lock. A writer reads the chain head, computes
 * the next hash and inserts. If another writer took the same seq first, the
 * unique index rejects the insert and the writer re-reads the head and retries.
 * That works the same on SQLite, Postgres, MySQL and D1.
 *
 * With `hmacKey`, hashes are HMAC-SHA256, so someone with database write access
 * but not the key cannot recompute a valid chain after editing rows.
 */

import { and, desc, eq, isNotNull } from "drizzle-orm";
import { compareCodeUnits } from "../compare.js";
import { hmacSha256, sha256 } from "../crypto/web-crypto.js";
import type { Database } from "../db/database.js";
import { auditLogs } from "../db/schema.js";

export type AuditInsert = typeof auditLogs.$inferInsert;
export type AuditRow = typeof auditLogs.$inferSelect;

export interface AuditChainConfig {
	/** Secret for HMAC-SHA256 hashing. Without it hashes are plain SHA-256. */
	hmacKey?: string;
}

const HASH_VERSION = 1;
const MAX_APPEND_ATTEMPTS = 30;

const registry = new WeakMap<object, AuditChainConfig>();
// Same-process writers for one agent queue up instead of racing. The unique
// index still guards against other processes.
const queues = new WeakMap<object, Map<string, Promise<unknown>>>();

/** Turn the chain on for a database handle. Called by createTheAuth when `audit.tamperEvident` is set. */
export function enableAuditChain(db: Database, config: AuditChainConfig = {}): void {
	registry.set(db, config);
}

export function getAuditChainConfig(db: Database): AuditChainConfig | undefined {
	return registry.get(db);
}

/** JSON with sorted keys at every depth, so equal data always serializes equally. */
export function canonicalJson(value: unknown): string {
	if (value === null || value === undefined) return "null";
	if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
	if (value instanceof Date) return JSON.stringify(value.toISOString());
	if (typeof value === "object") {
		const obj = value as Record<string, unknown>;
		const parts: string[] = [];
		for (const key of Object.keys(obj).sort(compareCodeUnits)) {
			if (obj[key] === undefined) continue;
			parts.push(`${JSON.stringify(key)}:${canonicalJson(obj[key])}`);
		}
		return `{${parts.join(",")}}`;
	}
	return JSON.stringify(value);
}

/** Row fields covered by the hash, normalized so insert-time and read-back values agree. */
function hashedFields(row: AuditInsert | AuditRow): Record<string, unknown> {
	const ts = row.timestamp instanceof Date ? row.timestamp.getTime() : Number(row.timestamp);
	return {
		id: row.id,
		agentId: row.agentId,
		userId: row.userId,
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

export async function computeRowHash(
	row: AuditInsert | AuditRow,
	chainSeq: number,
	prevHash: string | null,
	hmacKey?: string,
): Promise<string> {
	const payload = canonicalJson({
		v: HASH_VERSION,
		seq: chainSeq,
		prev: prevHash,
		row: hashedFields(row),
	});
	return hmacKey ? hmacSha256(hmacKey, payload) : sha256(payload);
}

function errorText(err: unknown): string {
	const parts: string[] = [];
	let cur: unknown = err;
	for (let i = 0; i < 4 && cur instanceof Error; i++) {
		parts.push(cur.message);
		const code = (cur as Error & { code?: unknown }).code;
		if (typeof code === "string") parts.push(code);
		cur = (cur as Error & { cause?: unknown }).cause;
	}
	return parts.join(" ");
}

function isUniqueViolation(err: unknown): boolean {
	return /unique|duplicate|23505|ER_DUP_ENTRY|SQLITE_CONSTRAINT_PRIMARYKEY/i.test(errorText(err));
}

async function readHead(
	db: Database,
	agentId: string,
): Promise<{ seq: number; hash: string } | null> {
	const rows = await db
		.select({ seq: auditLogs.chainSeq, hash: auditLogs.hash })
		.from(auditLogs)
		.where(and(eq(auditLogs.agentId, agentId), isNotNull(auditLogs.chainSeq)))
		.orderBy(desc(auditLogs.chainSeq))
		.limit(1);
	const head = rows[0];
	if (!head || head.seq === null || head.hash === null) return null;
	return { seq: head.seq, hash: head.hash };
}

/**
 * Insert an audit row. Plain insert unless the chain is enabled for this
 * database, in which case the row is linked to its agent's chain.
 */
export async function insertAuditRow(db: Database, values: AuditInsert): Promise<void> {
	const config = registry.get(db);
	if (!config) {
		await db.insert(auditLogs).values(values);
		return;
	}

	let byAgent = queues.get(db);
	if (!byAgent) {
		byAgent = new Map();
		queues.set(db, byAgent);
	}
	const previous = byAgent.get(values.agentId) ?? Promise.resolve();
	const run = previous.then(() => appendChained(db, values, config));
	const tail = run.catch(() => undefined);
	byAgent.set(values.agentId, tail);
	try {
		await run;
	} finally {
		if (byAgent.get(values.agentId) === tail) byAgent.delete(values.agentId);
	}
}

async function appendChained(
	db: Database,
	values: AuditInsert,
	config: AuditChainConfig,
): Promise<void> {
	// Whole seconds, because that is all the SQLite timestamp column keeps.
	// Hashing the truncated value keeps read-back rows verifiable.
	const stamped: AuditInsert = {
		...values,
		timestamp: new Date(Math.floor(values.timestamp.getTime() / 1000) * 1000),
	};

	let lastError: unknown;
	for (let attempt = 0; attempt < MAX_APPEND_ATTEMPTS; attempt++) {
		const head = await readHead(db, stamped.agentId);
		const chainSeq = head ? head.seq + 1 : 1;
		const prevHash = head ? head.hash : null;
		const hash = await computeRowHash(stamped, chainSeq, prevHash, config.hmacKey);
		try {
			await db.insert(auditLogs).values({ ...stamped, chainSeq, prevHash, hash });
			return;
		} catch (err) {
			if (!isUniqueViolation(err)) throw err;
			lastError = err;
			// Another process took this seq. Back off a little so racing writers spread out.
			await new Promise((resolve) => setTimeout(resolve, Math.random() * 4 * (attempt + 1)));
		}
	}
	throw new Error(
		`audit chain append gave up after ${MAX_APPEND_ATTEMPTS} attempts: ${errorText(lastError)}`,
	);
}
