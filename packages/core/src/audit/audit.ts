import { and, asc, desc, eq, gte, isNotNull, isNull, lt, lte } from "drizzle-orm";
import { generateId } from "../crypto/web-crypto.js";
import type { Database } from "../db/database.js";
import { auditLogs } from "../db/schema.js";
import type { AuditEntry, AuditExportOptions, AuditFilter } from "../types.js";
import { CHECKPOINT_ACTION, getAuditChainConfig, insertAuditRow } from "./chain.js";
import type { AuditChainExportOptions, ReplayOptions } from "./replay.js";
import { exportAudit, replayAgent } from "./replay.js";
import type { VerifyAuditChainOptions } from "./verify.js";
import { verifyAuditChain } from "./verify.js";

interface AuditModuleConfig {
	db: Database;
	/** HMAC key used when verifying and signing. Same value as `audit.hmacKey`. */
	hmacKey?: string;
}

/** Create the audit log module. Provides query and export capabilities for the immutable audit trail. */
export function createAuditModule(config: AuditModuleConfig) {
	const { db, hmacKey } = config;

	async function query(filter: AuditFilter): Promise<AuditEntry[]> {
		const conditions = [];

		if (filter.agentId) conditions.push(eq(auditLogs.agentId, filter.agentId));
		if (filter.userId) conditions.push(eq(auditLogs.userId, filter.userId));
		if (filter.since) conditions.push(gte(auditLogs.timestamp, filter.since));
		if (filter.until) conditions.push(lte(auditLogs.timestamp, filter.until));
		if (filter.result) conditions.push(eq(auditLogs.result, filter.result));

		let q = db.select().from(auditLogs).orderBy(desc(auditLogs.timestamp)).$dynamic();

		if (conditions.length > 0) {
			q = q.where(and(...conditions));
		}

		if (filter.limit) {
			q = q.limit(filter.limit);
		}
		if (filter.offset) {
			q = q.offset(filter.offset);
		}

		const rows = await q;

		return rows
			.filter((row) => {
				// Filter by actions if specified
				if (filter.actions && filter.actions.length > 0) {
					return filter.actions.includes(row.action);
				}
				return true;
			})
			.map(toAuditEntry);
	}

	async function exportLogs(options: AuditExportOptions): Promise<string> {
		const entries = await query({
			since: options.since,
			until: options.until,
			...(options.userId ? { userId: options.userId } : {}),
			limit: 10000, // cap exports
		});

		if (options.format === "json") {
			return JSON.stringify(entries, null, 2);
		}

		const headers = [
			"id",
			"agentId",
			"userId",
			"action",
			"resource",
			"result",
			"reason",
			"durationMs",
			"tokensCost",
			"timestamp",
		];
		const csvRows = [headers.join(",")];

		for (const entry of entries) {
			csvRows.push(
				[
					entry.id,
					entry.agentId,
					entry.userId,
					entry.action,
					entry.resource,
					entry.result,
					`"${(entry as AuditEntry & { reason?: string }).reason ?? ""}"`,
					entry.durationMs,
					entry.tokensCost ?? "",
					entry.timestamp.toISOString(),
				].join(","),
			);
		}

		return csvRows.join("\n");
	}

	/**
	 * Delete audit log entries older than the specified retention period. Returns the count of deleted rows.
	 * With the chain enabled, each agent's chain loses only its oldest contiguous run of expired rows, and a checkpoint row recording the last deleted seq and hash is appended first so verification still links. Expired rows that sit behind a newer row in seq order are kept until the rows in front of them expire.
	 */
	async function cleanup(options: {
		retentionDays: number;
	}): Promise<{ deleted: number; checkpoints?: number }> {
		const cutoff = new Date(Date.now() - options.retentionDays * 24 * 60 * 60 * 1000);
		const chain = getAuditChainConfig(db);
		let deleted = 0;
		let checkpoints = 0;

		if (chain) {
			const agentRows = await db
				.selectDistinct({ agentId: auditLogs.agentId })
				.from(auditLogs)
				.where(and(isNotNull(auditLogs.chainSeq), lt(auditLogs.timestamp, cutoff)));
			for (const { agentId } of agentRows) {
				const rows = await db
					.select({
						seq: auditLogs.chainSeq,
						hash: auditLogs.hash,
						userId: auditLogs.userId,
						timestamp: auditLogs.timestamp,
					})
					.from(auditLogs)
					.where(and(eq(auditLogs.agentId, agentId), isNotNull(auditLogs.chainSeq)))
					.orderBy(asc(auditLogs.chainSeq));
				let count = 0;
				let last: (typeof rows)[number] | undefined;
				for (const r of rows) {
					if (r.timestamp >= cutoff) break;
					count++;
					last = r;
				}
				if (!last || last.seq === null || last.hash === null || count === 0) continue;
				await insertAuditRow(db, {
					id: `chk_${generateId()}`,
					agentId,
					userId: last.userId,
					action: CHECKPOINT_ACTION,
					resource: `audit:${agentId}`,
					parameters: {
						throughSeq: last.seq,
						lastHash: last.hash,
						deletedCount: count,
						cutoff: cutoff.toISOString(),
					},
					result: "allowed",
					reason: "retention",
					durationMs: 0,
					timestamp: new Date(),
				});
				await db
					.delete(auditLogs)
					.where(and(eq(auditLogs.agentId, agentId), lte(auditLogs.chainSeq, last.seq)));
				deleted += count;
				checkpoints++;
			}
		}

		// Unchained rows, or every expired row when the chain is not enabled.
		const toDelete = await db
			.select({ id: auditLogs.id })
			.from(auditLogs)
			.where(
				chain
					? and(lt(auditLogs.timestamp, cutoff), isNull(auditLogs.chainSeq))
					: lt(auditLogs.timestamp, cutoff),
			);
		if (toDelete.length > 0) {
			await db
				.delete(auditLogs)
				.where(
					chain
						? and(lt(auditLogs.timestamp, cutoff), isNull(auditLogs.chainSeq))
						: lt(auditLogs.timestamp, cutoff),
				);
			deleted += toDelete.length;
		}

		return chain ? { deleted, checkpoints } : { deleted };
	}

	return {
		query,
		export: exportLogs,
		cleanup,
		verifyAuditChain: (opts: VerifyAuditChainOptions) => verifyAuditChain(db, opts, hmacKey),
		replayAgent: (agentId: string, opts: ReplayOptions = {}) =>
			replayAgent(db, agentId, opts, hmacKey),
		exportAudit: (opts: AuditChainExportOptions = {}) => exportAudit(db, opts, hmacKey),
	};
}

function toAuditEntry(row: typeof auditLogs.$inferSelect): AuditEntry {
	return {
		id: row.id,
		agentId: row.agentId,
		userId: row.userId,
		action: row.action,
		resource: row.resource,
		parameters: (row.parameters as Record<string, unknown>) ?? {},
		result: row.result as AuditEntry["result"],
		reason: row.reason ?? undefined,
		durationMs: row.durationMs,
		tokensCost: row.tokensCost ?? undefined,
		timestamp: row.timestamp,
	};
}
