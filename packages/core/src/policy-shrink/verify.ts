import type { Database } from "../db/database.js";
import type { Permission } from "../types.js";
import { classifyRow, createGrantMatcher, wholeOr } from "./permissions.js";
import { readDecisionRows } from "./rows.js";
import type {
	BlastRadiusReport,
	DecisionRow,
	PreviewOptions,
	PreviewReport,
	RowRef,
	VerifyOptions,
} from "./types.js";

const DEFAULT_EXAMPLES = 1000;

function ref(row: DecisionRow): RowRef {
	return { id: row.id, action: row.action, resource: row.resource, timestamp: row.timestamp };
}

/**
 * Incremental replay of decision rows against a proposed permission set.
 * Matching only (action and resource, same first-match result as the engine's findMatchingPermission).
 * Constraints depend on live state, so they are not re-evaluated.
 */
export function createReplay(proposed: Permission[], opts: VerifyOptions = {}) {
	const max = wholeOr(opts.maxExamples, DEFAULT_EXAMPLES);
	const find = createGrantMatcher(proposed);
	const perPermission = proposed.map((p) => ({ permission: p, allows: 0 }));
	const report: BlastRadiusReport = {
		replayedAllows: 0,
		stillAllowed: 0,
		newlyDeniedCount: 0,
		newlyDenied: [],
		wouldAlsoAllowCount: 0,
		wouldAlsoAllowPreviouslyDenied: [],
		ignoredRows: 0,
		perPermission,
		truncated: false,
	};

	function add(row: DecisionRow): void {
		const kind = classifyRow(row);
		if (kind === "internal" || kind === "deny_other") {
			report.ignoredRows++;
			return;
		}
		const hit = find(row.action, row.resource);
		if (kind === "allow") {
			report.replayedAllows++;
			if (hit) {
				report.stillAllowed++;
				const slot = perPermission[hit.index];
				if (slot) slot.allows++;
			} else {
				report.newlyDeniedCount++;
				if (report.newlyDenied.length < max) report.newlyDenied.push(ref(row));
				else report.truncated = true;
			}
			return;
		}
		if (hit) {
			report.wouldAlsoAllowCount++;
			if (report.wouldAlsoAllowPreviouslyDenied.length < max) {
				report.wouldAlsoAllowPreviouslyDenied.push(ref(row));
			} else report.truncated = true;
		}
	}

	return { add, finish: () => report };
}

/**
 * Prove a proposed permission set against recorded decisions: does it still
 * allow every historical allow, and does it newly allow any call that was
 * denied for lack of a grant? Pure and deterministic. Rows are examined in
 * the order given.
 */
export function verifyShrink(
	rows: Iterable<DecisionRow>,
	proposed: Permission[],
	opts: VerifyOptions = {},
): BlastRadiusReport {
	const replay = createReplay(proposed, opts);
	for (const row of rows) replay.add(row);
	return replay.finish();
}

/**
 * Blast radius of any permission change: which recorded decisions of this
 * agent would flip if `proposed` were its permission set. Reads rows in pages.
 * Works for a shrink, a widening or a rewrite.
 */
export async function previewPolicyChange(
	db: Database,
	agentId: string,
	proposed: Permission[],
	opts: PreviewOptions = {},
): Promise<PreviewReport> {
	const replay = createReplay(proposed, opts);
	let rowsScanned = 0;
	for await (const page of readDecisionRows(db, agentId, opts)) {
		for (const row of page) {
			rowsScanned++;
			replay.add(row);
		}
	}
	return {
		...replay.finish(),
		agentId,
		window: { since: opts.since ?? null, until: opts.until ?? null },
		rowsScanned,
	};
}
