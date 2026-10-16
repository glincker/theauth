import { and, asc, eq, gt, gte, lte, or } from "drizzle-orm";
import type { Database } from "../db/database.js";
import { auditLogs } from "../db/schema.js";
import { wholeOr } from "./permissions.js";
import type { DecisionRow } from "./types.js";

const DEFAULT_PAGE = 1000;

export interface ReadRowsOptions {
	since?: Date;
	until?: Date;
	pageSize?: number;
}

/**
 * Read an agent's audit rows oldest first, one page at a time. Uses a
 * (timestamp, id) keyset cursor, so memory is bounded by the page size no
 * matter how large the window is, and rows that share a timestamp are never
 * skipped or repeated.
 */
export async function* readDecisionRows(
	db: Database,
	agentId: string,
	opts: ReadRowsOptions = {},
): AsyncGenerator<DecisionRow[]> {
	const pageSize = wholeOr(opts.pageSize, DEFAULT_PAGE, 1);
	let cursor: { at: Date; id: string } | null = null;
	for (;;) {
		const conds = [eq(auditLogs.agentId, agentId)];
		if (opts.since) conds.push(gte(auditLogs.timestamp, opts.since));
		if (opts.until) conds.push(lte(auditLogs.timestamp, opts.until));
		if (cursor) {
			const after = or(
				gt(auditLogs.timestamp, cursor.at),
				and(eq(auditLogs.timestamp, cursor.at), gt(auditLogs.id, cursor.id)),
			);
			if (after) conds.push(after);
		}
		const page = await db
			.select({
				id: auditLogs.id,
				action: auditLogs.action,
				resource: auditLogs.resource,
				result: auditLogs.result,
				reason: auditLogs.reason,
				timestamp: auditLogs.timestamp,
				delegationChain: auditLogs.delegationChain,
			})
			.from(auditLogs)
			.where(and(...conds))
			.orderBy(asc(auditLogs.timestamp), asc(auditLogs.id))
			.limit(pageSize);
		if (page.length === 0) return;
		yield page;
		const last = page[page.length - 1];
		if (!last || page.length < pageSize) return;
		cursor = { at: last.timestamp, id: last.id };
	}
}
