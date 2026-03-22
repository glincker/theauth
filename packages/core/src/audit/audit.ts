import { and, desc, eq, gte, lt, lte } from "drizzle-orm";
import type { Database } from "../db/database.js";
import { auditLogs } from "../db/schema.js";
import type {
	AuditEntry,
	AuditExportOptions,
	AuditFilter,
	CostFilter,
	CostSummary,
} from "../types.js";

interface AuditModuleConfig {
	db: Database;
}

/**
 * Create the audit log module.
 * Provides query and export capabilities for the immutable audit trail.
 */
export function createAuditModule(config: AuditModuleConfig) {
	const { db } = config;

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
			limit: 10000, // cap exports
		});

		if (options.format === "json") {
			return JSON.stringify(entries, null, 2);
		}

		// CSV format
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
	 * Delete audit log entries older than the specified retention period.
	 * Returns the count of deleted rows.
	 */
	async function cleanup(options: { retentionDays: number }): Promise<{ deleted: number }> {
		const cutoff = new Date(Date.now() - options.retentionDays * 24 * 60 * 60 * 1000);

		// Count rows to be deleted before removing them
		const toDelete = await db
			.select({ id: auditLogs.id })
			.from(auditLogs)
			.where(lt(auditLogs.timestamp, cutoff));

		if (toDelete.length === 0) {
			return { deleted: 0 };
		}

		await db.delete(auditLogs).where(lt(auditLogs.timestamp, cutoff));

		return { deleted: toDelete.length };
	}

	/**
	 * Aggregate token costs from the audit log.
	 *
	 * Returns the total cost across all matching entries, broken down by agent
	 * and by calendar day (UTC). Only entries where `tokensCost` is not null
	 * are included in cost totals; all matching entries count toward `callCount`.
	 */
	async function getCostSummary(filter?: CostFilter): Promise<CostSummary> {
		const conditions = [];

		if (filter?.agentId) conditions.push(eq(auditLogs.agentId, filter.agentId));
		if (filter?.userId) conditions.push(eq(auditLogs.userId, filter.userId));
		if (filter?.since) conditions.push(gte(auditLogs.timestamp, filter.since));
		if (filter?.until) conditions.push(lte(auditLogs.timestamp, filter.until));

		let q = db.select().from(auditLogs).$dynamic();

		if (conditions.length > 0) {
			q = q.where(and(...conditions));
		}

		const rows = await q;

		// Total across all matching rows (only where tokensCost is set)
		let totalCost = 0;

		// Aggregate by agentId
		const agentMap = new Map<string, { totalCost: number; callCount: number }>();
		// Aggregate by UTC date string "YYYY-MM-DD"
		const dayMap = new Map<string, { totalCost: number; callCount: number }>();

		for (const row of rows) {
			const cost = row.tokensCost ?? 0;
			totalCost += cost;

			// Per-agent
			const agentEntry = agentMap.get(row.agentId) ?? { totalCost: 0, callCount: 0 };
			agentEntry.totalCost += cost;
			agentEntry.callCount += 1;
			agentMap.set(row.agentId, agentEntry);

			// Per-day (UTC)
			const date = row.timestamp.toISOString().slice(0, 10);
			const dayEntry = dayMap.get(date) ?? { totalCost: 0, callCount: 0 };
			dayEntry.totalCost += cost;
			dayEntry.callCount += 1;
			dayMap.set(date, dayEntry);
		}

		const byAgent = Array.from(agentMap.entries())
			.map(([agentId, v]) => ({ agentId, ...v }))
			.sort((a, b) => b.totalCost - a.totalCost);

		const byDay = Array.from(dayMap.entries())
			.map(([date, v]) => ({ date, ...v }))
			.sort((a, b) => a.date.localeCompare(b.date));

		return { totalCost, byAgent, byDay };
	}

	return { query, export: exportLogs, cleanup, getCostSummary };
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
