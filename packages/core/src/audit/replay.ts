import { and, asc, eq, gte, lte, or } from "drizzle-orm";
import { hmacSha256, sha256 } from "../crypto/web-crypto.js";
import type { Database } from "../db/database.js";
import { approvalRequests, auditLogs, costEvents, delegationChains } from "../db/schema.js";
import type { Result } from "../mcp/types.js";
import { canonicalJson } from "./chain.js";
import type { ChainBreak, ChainHead, VerifyAuditChainResult } from "./verify.js";
import { verifyAuditChain } from "./verify.js";

export interface ReplayOptions {
	since?: Date;
	until?: Date;
	/** Only show what the agent did for this user. Applies to audit rows and approvals. */
	userId?: string;
}

export type TimelineKind = "action" | "decision" | "delegation" | "approval" | "token";

export interface TimelineEvent {
	kind: TimelineKind;
	at: Date;
	id: string;
	summary: string;
	userId?: string;
	/** True for rows covered by the hash chain (audit rows written with tamperEvident on). */
	chained: boolean;
	detail: Record<string, unknown>;
}

export interface ChainVerification {
	status: "verified" | "broken" | "unchained";
	checked: number;
	unchained: number;
	firstBreak?: ChainBreak;
	heads: ChainHead[];
}

export interface AgentReplay {
	agentId: string;
	events: TimelineEvent[];
	verification: ChainVerification;
}

const KIND_ORDER: Record<TimelineKind, number> = {
	delegation: 0,
	approval: 1,
	action: 2,
	decision: 2,
	token: 3,
};

function summarize(v: VerifyAuditChainResult): ChainVerification {
	const status = !v.ok ? "broken" : v.checked === 0 ? "unchained" : "verified";
	return {
		status,
		checked: v.checked,
		unchained: v.unchained,
		firstBreak: v.firstBreak,
		heads: v.heads,
	};
}

/**
 * Ordered timeline of what one agent did: audit rows (actions and denials),
 * delegations it gave or received, approval requests and answers, and token
 * cost events. Only audit rows are covered by the hash chain, and the
 * verification block says so.
 */
export async function replayAgent(
	db: Database,
	agentId: string,
	opts: ReplayOptions,
	hmacKey?: string,
): Promise<Result<AgentReplay>> {
	try {
		const events: TimelineEvent[] = [];
		const inRange = (col: typeof auditLogs.timestamp | typeof costEvents.recordedAt) => {
			const c = [];
			if (opts.since) c.push(gte(col, opts.since));
			if (opts.until) c.push(lte(col, opts.until));
			return c;
		};

		const auditRows = await db
			.select()
			.from(auditLogs)
			.where(
				and(
					eq(auditLogs.agentId, agentId),
					...(opts.userId ? [eq(auditLogs.userId, opts.userId)] : []),
					...inRange(auditLogs.timestamp),
				),
			)
			.orderBy(asc(auditLogs.timestamp), asc(auditLogs.chainSeq), asc(auditLogs.id));
		for (const r of auditRows) {
			events.push({
				kind: r.result === "allowed" ? "action" : "decision",
				at: r.timestamp,
				id: r.id,
				userId: r.userId,
				summary: `${r.result} ${r.action} ${r.resource}${r.reason ? ` (${r.reason})` : ""}`,
				chained: r.hash !== null,
				detail: {
					action: r.action,
					resource: r.resource,
					result: r.result,
					reason: r.reason,
					parameters: r.parameters,
					durationMs: r.durationMs,
					chainSeq: r.chainSeq,
					hash: r.hash,
				},
			});
		}

		const dels = await db
			.select()
			.from(delegationChains)
			.where(
				or(eq(delegationChains.fromAgentId, agentId), eq(delegationChains.toAgentId, agentId)),
			);
		for (const d of dels) {
			if (opts.since && d.createdAt < opts.since) continue;
			if (opts.until && d.createdAt > opts.until) continue;
			const gave = d.fromAgentId === agentId;
			events.push({
				kind: "delegation",
				at: d.createdAt,
				id: d.id,
				summary: gave
					? `delegated to ${d.toAgentId} (${d.status})`
					: `received delegation from ${d.fromAgentId} (${d.status})`,
				chained: false,
				detail: {
					fromAgentId: d.fromAgentId,
					toAgentId: d.toAgentId,
					permissions: d.permissions,
					depth: d.depth,
					status: d.status,
					expiresAt: d.expiresAt.toISOString(),
				},
			});
		}

		const approvals = await db
			.select()
			.from(approvalRequests)
			.where(
				and(
					eq(approvalRequests.agentId, agentId),
					...(opts.userId ? [eq(approvalRequests.userId, opts.userId)] : []),
				),
			);
		for (const a of approvals) {
			const requestInRange =
				(!opts.since || a.createdAt >= opts.since) && (!opts.until || a.createdAt <= opts.until);
			if (requestInRange) {
				events.push({
					kind: "approval",
					at: a.createdAt,
					id: `${a.id}:requested`,
					userId: a.userId,
					summary: `approval requested for ${a.action} ${a.resource}`,
					chained: false,
					detail: { approvalId: a.id, action: a.action, resource: a.resource },
				});
			}
			const answeredAt = a.respondedAt;
			if (
				answeredAt &&
				(!opts.since || answeredAt >= opts.since) &&
				(!opts.until || answeredAt <= opts.until)
			) {
				events.push({
					kind: "approval",
					at: answeredAt,
					id: `${a.id}:${a.status}`,
					userId: a.userId,
					summary: `approval ${a.status} for ${a.action} ${a.resource}`,
					chained: false,
					detail: { approvalId: a.id, status: a.status, respondedBy: a.respondedBy },
				});
			}
		}

		const costs = await db
			.select()
			.from(costEvents)
			.where(and(eq(costEvents.agentId, agentId), ...inRange(costEvents.recordedAt)));
		for (const c of costs) {
			events.push({
				kind: "token",
				at: c.recordedAt,
				id: c.id,
				summary: `${c.tool} in=${c.inputTokens ?? 0} out=${c.outputTokens ?? 0} cost_micros=${c.costMicros}`,
				chained: false,
				detail: {
					tool: c.tool,
					inputTokens: c.inputTokens,
					outputTokens: c.outputTokens,
					costMicros: c.costMicros,
					currency: c.currency,
				},
			});
		}

		events.sort(
			(a, b) =>
				a.at.getTime() - b.at.getTime() ||
				KIND_ORDER[a.kind] - KIND_ORDER[b.kind] ||
				a.id.localeCompare(b.id),
		);

		const verified = await verifyAuditChain(
			db,
			{ agentId, from: opts.since, to: opts.until },
			hmacKey,
		);
		if (!verified.success) return verified;

		return {
			success: true,
			data: { agentId, events, verification: summarize(verified.data) },
		};
	} catch (error) {
		return {
			success: false,
			error: {
				code: "AUDIT_REPLAY_FAILED",
				message: error instanceof Error ? error.message : "Unknown",
			},
		};
	}
}

// ─── Export ──────────────────────────────────────────────────────────────────

export interface AuditChainExportOptions {
	since?: Date;
	until?: Date;
	agentId?: string;
	/** Key that signs the manifest. Defaults to the configured audit hmacKey. */
	signingKey?: string;
}

export interface AuditManifest {
	version: 1;
	createdAt: string;
	range: { from: string | null; to: string | null };
	agentId: string | null;
	rowCount: number;
	/** SHA-256 of the exact JSONL text. */
	fileSha256: string;
	/** Chain head per agent at the end of the exported range. */
	heads: ChainHead[];
	chainVerified: boolean;
	unchainedRows: number;
	algorithm: "hmac-sha256";
	/** HMAC-SHA256 over the canonical JSON of every other manifest field. */
	signature: string;
}

export interface AuditExport {
	jsonl: string;
	manifest: AuditManifest;
}

const EXPORT_CAP = 100_000;

/**
 * Export audit rows as JSONL (one canonical JSON object per line, oldest first
 * within each agent) plus a signed manifest. Timestamps are ISO strings; to
 * recompute a row hash outside this library, convert them back to epoch ms.
 */
export async function exportAudit(
	db: Database,
	opts: AuditChainExportOptions,
	hmacKey?: string,
): Promise<Result<AuditExport>> {
	const key = opts.signingKey ?? hmacKey;
	if (!key) {
		return {
			success: false,
			error: {
				code: "NO_SIGNING_KEY",
				message: "exportAudit needs a signing key: set audit.hmacKey or pass signingKey",
			},
		};
	}
	try {
		const conds = [];
		if (opts.agentId) conds.push(eq(auditLogs.agentId, opts.agentId));
		if (opts.since) conds.push(gte(auditLogs.timestamp, opts.since));
		if (opts.until) conds.push(lte(auditLogs.timestamp, opts.until));
		const rows = await db
			.select()
			.from(auditLogs)
			.where(conds.length ? and(...conds) : undefined)
			.orderBy(asc(auditLogs.agentId), asc(auditLogs.chainSeq), asc(auditLogs.timestamp))
			.limit(EXPORT_CAP + 1);
		if (rows.length > EXPORT_CAP) {
			return {
				success: false,
				error: {
					code: "EXPORT_TOO_LARGE",
					message: `More than ${EXPORT_CAP} rows in range, narrow it with since/until/agentId`,
				},
			};
		}

		const jsonl = rows
			.map((r) =>
				canonicalJson({
					id: r.id,
					agentId: r.agentId,
					userId: r.userId,
					action: r.action,
					resource: r.resource,
					parameters: r.parameters,
					result: r.result,
					reason: r.reason,
					durationMs: r.durationMs,
					tokensCost: r.tokensCost,
					ip: r.ip,
					userAgent: r.userAgent,
					cacheHit: r.cacheHit,
					timestamp: r.timestamp.toISOString(),
					chainSeq: r.chainSeq,
					prevHash: r.prevHash,
					hash: r.hash,
				}),
			)
			.join("\n");
		const text = rows.length ? `${jsonl}\n` : "";

		const verified = await verifyAuditChain(
			db,
			{ agentId: opts.agentId, from: opts.since, to: opts.until },
			hmacKey,
		);
		if (!verified.success) return verified;

		const body: Omit<AuditManifest, "signature"> = {
			version: 1,
			createdAt: new Date().toISOString(),
			range: {
				from: opts.since ? opts.since.toISOString() : null,
				to: opts.until ? opts.until.toISOString() : null,
			},
			agentId: opts.agentId ?? null,
			rowCount: rows.length,
			fileSha256: await sha256(text),
			heads: verified.data.heads,
			chainVerified: verified.data.ok,
			unchainedRows: verified.data.unchained,
			algorithm: "hmac-sha256",
		};
		const signature = await hmacSha256(key, canonicalJson(body));
		return { success: true, data: { jsonl: text, manifest: { ...body, signature } } };
	} catch (error) {
		return {
			success: false,
			error: {
				code: "AUDIT_EXPORT_FAILED",
				message: error instanceof Error ? error.message : "Unknown",
			},
		};
	}
}

/** Check an export offline: file hash, manifest signature and row count. */
export async function verifyAuditExport(
	exported: AuditExport,
	signingKey: string,
): Promise<{ ok: boolean; problems: string[] }> {
	const problems: string[] = [];
	const { signature, ...body } = exported.manifest;
	if ((await hmacSha256(signingKey, canonicalJson(body))) !== signature) {
		problems.push("manifest signature does not match");
	}
	if ((await sha256(exported.jsonl)) !== exported.manifest.fileSha256) {
		problems.push("file hash does not match manifest");
	}
	const lines = exported.jsonl === "" ? 0 : exported.jsonl.trimEnd().split("\n").length;
	if (lines !== exported.manifest.rowCount) {
		problems.push(`row count ${lines} does not match manifest ${exported.manifest.rowCount}`);
	}
	return { ok: problems.length === 0, problems };
}
