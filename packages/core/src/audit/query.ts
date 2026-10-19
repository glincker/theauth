/**
 * Audit read side: filters, order and keyset (cursor) paging.
 *
 * Rows sort by (recorded_at_ms, id). `recorded_at_ms` is strictly increasing per agent chain and per process, so ties only happen across writers, and `id` breaks them, which makes the order total and the cursor stable when rows are written between pages. The cursor is the (recorded_at_ms, id) pair of the last row on a page, wrapped in an opaque string.
 */

import type { SQL } from "drizzle-orm";
import { and, asc, desc, eq, gte, inArray, lte, or, sql } from "drizzle-orm";
import type { Database } from "../db/database.js";
import { auditLogs } from "../db/schema.js";
import { isDecisionCode } from "../permission/codes.js";
import type { AuditEntry, AuditFilter, AuditInputRef, AuditPage } from "../types.js";
import { isInputSourceKind, provenanceContentHashes, provenanceNeedles } from "./provenance.js";

const CURSOR_PREFIX = "c1.";
const LIKE_ESCAPE = "!";

/** Error thrown for a cursor that was not produced by `audit.page`. HTTP routes map it to 400. */
export function invalidAuditCursor(): Error & { code: "INVALID_CURSOR" } {
	return Object.assign(new Error("Invalid audit cursor"), { code: "INVALID_CURSOR" as const });
}

export function isInvalidAuditCursor(err: unknown): boolean {
	return err instanceof Error && (err as { code?: unknown }).code === "INVALID_CURSOR";
}

interface CursorPosition {
	ms: number;
	id: string;
}

function toBase64Url(text: string): string {
	const bytes = new TextEncoder().encode(text);
	let binary = "";
	for (const b of bytes) binary += String.fromCharCode(b);
	return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromBase64Url(text: string): string {
	const padded = text.replace(/-/g, "+").replace(/_/g, "/");
	const binary = atob(padded + "=".repeat((4 - (padded.length % 4)) % 4));
	return new TextDecoder().decode(Uint8Array.from(binary, (c) => c.charCodeAt(0)));
}

export function encodeAuditCursor(pos: CursorPosition): string {
	return CURSOR_PREFIX + toBase64Url(JSON.stringify([pos.ms, pos.id]));
}

export function decodeAuditCursor(cursor: string): CursorPosition {
	if (!cursor.startsWith(CURSOR_PREFIX)) throw invalidAuditCursor();
	try {
		const parsed: unknown = JSON.parse(fromBase64Url(cursor.slice(CURSOR_PREFIX.length)));
		if (
			Array.isArray(parsed) &&
			parsed.length === 2 &&
			typeof parsed[0] === "number" &&
			Number.isFinite(parsed[0]) &&
			typeof parsed[1] === "string"
		) {
			return { ms: parsed[0], id: parsed[1] };
		}
	} catch {
		// fall through to the typed error
	}
	throw invalidAuditCursor();
}

function escapeLike(text: string): string {
	return text.replace(/[!%_]/g, (c) => `${LIKE_ESCAPE}${c}`);
}

function isMysql(db: Database): boolean {
	const dialect = (db as unknown as { dialect?: { constructor?: { name?: string } } }).dialect;
	return dialect?.constructor?.name === "MySqlDialect";
}

function buildConditions(
	filter: AuditFilter,
	cursor: CursorPosition | null,
	contentHashes: readonly string[] = [],
	textType: "TEXT" | "CHAR" = "TEXT",
): SQL[] {
	const conditions: SQL[] = [];
	if (filter.agentId) conditions.push(eq(auditLogs.agentId, filter.agentId));
	if (filter.userId) conditions.push(eq(auditLogs.userId, filter.userId));
	if (filter.since) conditions.push(gte(auditLogs.timestamp, filter.since));
	if (filter.until) conditions.push(lte(auditLogs.timestamp, filter.until));
	if (filter.result) conditions.push(eq(auditLogs.result, filter.result));
	if (filter.codes && filter.codes.length > 0) {
		conditions.push(inArray(auditLogs.decisionCode, filter.codes));
	}
	if (filter.events && filter.events.length > 0) {
		conditions.push(inArray(auditLogs.event, filter.events));
	}
	if (filter.actions && filter.actions.length > 0) {
		conditions.push(inArray(auditLogs.action, filter.actions));
	}
	if (filter.resource) {
		if (filter.resource.endsWith("*")) {
			const prefix = escapeLike(filter.resource.slice(0, -1));
			conditions.push(sql`${auditLogs.resource} LIKE ${`${prefix}%`} ESCAPE '!'`);
		} else {
			conditions.push(eq(auditLogs.resource, filter.resource));
		}
	}
	if (filter.provenance) {
		const needles = provenanceNeedles(filter.provenance, contentHashes);
		// The column is JSON on every dialect. Casting to text keeps the match portable; the needles have no LIKE wildcards.
		// MySQL has no CAST AS TEXT, its string target is CHAR.
		const matches = needles.map(
			(needle) =>
				sql`CAST(${auditLogs.inputProvenance} AS ${sql.raw(textType)}) LIKE ${`%${needle}%`}`,
		);
		const any = matches.length > 1 ? or(...matches) : matches[0];
		if (any) conditions.push(any);
	}
	if (cursor) {
		const desc_ = (filter.order ?? "desc") === "desc";
		const beyondMs = desc_
			? sql`${auditLogs.recordedAtMs} < ${cursor.ms}`
			: sql`${auditLogs.recordedAtMs} > ${cursor.ms}`;
		const beyondId = desc_
			? sql`${auditLogs.id} < ${cursor.id}`
			: sql`${auditLogs.id} > ${cursor.id}`;
		const next = or(beyondMs, and(eq(auditLogs.recordedAtMs, cursor.ms), beyondId));
		if (next) conditions.push(next);
	}
	return conditions;
}

/** Newest first unless `filter.order` is "asc". Ties on recorded_at_ms fall back to id. */
async function selectRows(
	db: Database,
	filter: AuditFilter,
	cursor: CursorPosition | null,
	limit: number | undefined,
	offset: number | undefined,
) {
	const dir = (filter.order ?? "desc") === "asc" ? asc : desc;
	let q = db
		.select()
		.from(auditLogs)
		.orderBy(dir(auditLogs.recordedAtMs), dir(auditLogs.id))
		.$dynamic();
	const contentHashes = filter.provenance
		? await provenanceContentHashes(db, filter.provenance)
		: [];
	const conditions = buildConditions(filter, cursor, contentHashes, isMysql(db) ? "CHAR" : "TEXT");
	if (conditions.length > 0) q = q.where(and(...conditions));
	if (limit) q = q.limit(limit);
	if (offset) q = q.offset(offset);
	return q;
}

export async function queryAuditEntries(db: Database, filter: AuditFilter): Promise<AuditEntry[]> {
	const cursor = filter.cursor ? decodeAuditCursor(filter.cursor) : null;
	const rows = await selectRows(
		db,
		filter,
		cursor,
		filter.limit,
		cursor ? undefined : filter.offset,
	);
	return rows.map(toAuditEntry);
}

export async function pageAuditEntries(db: Database, filter: AuditFilter): Promise<AuditPage> {
	const cursor = filter.cursor ? decodeAuditCursor(filter.cursor) : null;
	const limit = filter.limit;
	const rows = await selectRows(
		db,
		filter,
		cursor,
		limit ? limit + 1 : undefined,
		cursor ? undefined : filter.offset,
	);
	const more = limit !== undefined && limit > 0 && rows.length > limit;
	const kept = more ? rows.slice(0, limit) : rows;
	const last = kept[kept.length - 1];
	const nextCursor =
		more && last && last.recordedAtMs !== null
			? encodeAuditCursor({ ms: last.recordedAtMs, id: last.id })
			: null;
	return { entries: kept.map(toAuditEntry), nextCursor };
}

function inputsOf(raw: unknown): AuditInputRef[] | undefined {
	const sources = (raw as { sources?: unknown } | null)?.sources;
	if (!Array.isArray(sources)) return undefined;
	const out: AuditInputRef[] = [];
	for (const s of sources) {
		if (typeof s !== "object" || s === null) continue;
		const { kind, id, hash, hv } = s as Record<string, unknown>;
		if (!isInputSourceKind(kind) || typeof hash !== "string") continue;
		out.push({
			kind,
			...(typeof id === "string" ? { id } : {}),
			hash,
			...(hv === 2 ? { hv: 2 as const } : {}),
		});
	}
	return out.length > 0 ? out : undefined;
}

export function toAuditEntry(row: typeof auditLogs.$inferSelect): AuditEntry {
	return {
		id: row.id,
		agentId: row.agentId,
		userId: row.userId,
		action: row.action,
		resource: row.resource,
		parameters: (row.parameters as Record<string, unknown>) ?? {},
		result: row.result as AuditEntry["result"],
		reason: row.reason ?? undefined,
		code: isDecisionCode(row.decisionCode) ? row.decisionCode : undefined,
		event: row.event ?? null,
		durationMs: row.durationMs,
		tokensCost: row.tokensCost ?? undefined,
		...(inputsOf(row.inputProvenance) ? { inputs: inputsOf(row.inputProvenance) } : {}),
		timestamp: row.timestamp,
	};
}
