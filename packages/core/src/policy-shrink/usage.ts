import { and, eq } from "drizzle-orm";
import type { Database } from "../db/database.js";
import { delegationChains, permissions as permissionsTable } from "../db/schema.js";
import { compareStrings } from "../internal-compare.js";
import type { Permission } from "../types.js";
import { atomKey, classifyRow, createGrantMatcher, splitPermission } from "./permissions.js";
import { readDecisionRows } from "./rows.js";
import type {
	AnalyzeOptions,
	DecisionRow,
	Grant,
	UncoveredAllow,
	UsageAnalysis,
	UsedPermission,
} from "./types.js";

/** Most delegation chain ids kept per grant, so a hostile or huge log cannot grow one set without bound. */
const CHAINS_PER_GRANT_CAP = 1000;

/** Distinct pairs kept for `deniedNoGrant` and `uncovered`, so memory stays bounded. */
const DISTINCT_CAP = 5000;

/**
 * The agent's effective permissions as single-action grants. Own permissions come first, then permissions delegated through active, unexpired chains, which is the order `authorize()` tries them in. Rows are read without an ORDER BY, like the engine's own lookup, so first-match attribution agrees with it. Expired or revoked delegations are not included.
 */
export async function loadGrants(
	db: Database,
	agentId: string,
	now: Date = new Date(),
): Promise<Grant[]> {
	const own = await db.select().from(permissionsTable).where(eq(permissionsTable.agentId, agentId));
	const chains = await db
		.select()
		.from(delegationChains)
		.where(and(eq(delegationChains.toAgentId, agentId), eq(delegationChains.status, "active")));

	const grants: Grant[] = [];
	const seen = new Set<string>();
	const push = (p: Permission, source: Grant["source"]) => {
		for (const atom of splitPermission(p)) {
			const key = atomKey(atom);
			if (seen.has(key)) continue;
			seen.add(key);
			grants.push({ permission: atom, source });
		}
	};
	for (const r of own) {
		const p: Permission = { resource: r.resource, actions: r.actions };
		if (r.constraints) p.constraints = r.constraints;
		if (r.relation) p.relation = r.relation;
		push(p, { kind: "own" });
	}
	for (const c of chains) {
		if (c.expiresAt <= now) continue;
		for (const p of c.permissions as Permission[]) {
			push(p, { kind: "delegation", chainId: c.id });
		}
	}
	return grants;
}

interface UseState {
	count: number;
	first: Date;
	last: Date;
	chains: Set<string>;
}

/**
 * Pure accumulator behind analyzeUsage. Feed it rows in any order, then call `finish`. Matching gives the same first-match result as findMatchingPermission, the function the engine uses, so a row is attributed to the same grant `authorize()` would pick.
 */
export function createUsageAccumulator(
	agentId: string,
	grants: Grant[],
	window: { since?: Date; until?: Date } = {},
) {
	const atoms = grants.map((g) => g.permission);
	const find = createGrantMatcher(atoms);
	const used = new Map<number, UseState>();
	const attempted = new Set<number>();
	const denied = new Map<string, { action: string; resource: string }>();
	const uncovered = new Map<string, UncoveredAllow>();
	const ev = {
		rowsScanned: 0,
		allowedRows: 0,
		noGrantDenials: 0,
		otherDenials: 0,
		internalRows: 0,
		uncoveredAllows: 0,
	};

	function add(row: DecisionRow): void {
		ev.rowsScanned++;
		const kind = classifyRow(row);
		if (kind === "internal") {
			ev.internalRows++;
			return;
		}
		if (kind === "deny_no_grant") {
			ev.noGrantDenials++;
			const key = JSON.stringify([row.action, row.resource]);
			if (!denied.has(key) && denied.size < DISTINCT_CAP) {
				denied.set(key, { action: row.action, resource: row.resource });
			}
			return;
		}
		const hit = find(row.action, row.resource);
		if (kind === "deny_other") {
			// Denied for another cause: the grant was exercised, so it is not proof of non-use.
			ev.otherDenials++;
			if (hit) attempted.add(hit.index);
			return;
		}
		ev.allowedRows++;
		if (!hit) {
			ev.uncoveredAllows++;
			const key = JSON.stringify([row.action, row.resource]);
			const u = uncovered.get(key);
			if (u) u.count++;
			else if (uncovered.size < DISTINCT_CAP) {
				uncovered.set(key, { action: row.action, resource: row.resource, count: 1 });
			}
			return;
		}
		let s = used.get(hit.index);
		if (!s) {
			s = { count: 0, first: row.timestamp, last: row.timestamp, chains: new Set() };
			used.set(hit.index, s);
		}
		s.count++;
		if (row.timestamp < s.first) s.first = row.timestamp;
		if (row.timestamp > s.last) s.last = row.timestamp;
		const src = grants[hit.index]?.source;
		if (src?.chainId && s.chains.size < CHAINS_PER_GRANT_CAP) s.chains.add(src.chainId);
		if (src?.kind === "delegation") {
			for (const id of row.delegationChain ?? []) {
				if (s.chains.size >= CHAINS_PER_GRANT_CAP) break;
				s.chains.add(id);
			}
		}
	}

	function finish(): UsageAnalysis {
		const usedOut: UsedPermission[] = [];
		const unused: Permission[] = [];
		const attemptedOnly: Permission[] = [];
		grants.forEach((g, i) => {
			const s = used.get(i);
			if (s) {
				usedOut.push({
					permission: g.permission,
					count: s.count,
					firstSeen: s.first,
					lastSeen: s.last,
					via: [...s.chains].sort(compareStrings),
				});
			} else if (attempted.has(i)) {
				attemptedOnly.push(g.permission);
			} else {
				unused.push(g.permission);
			}
		});
		const sortPair = (a: { action: string; resource: string }, b: typeof a) =>
			a.resource.localeCompare(b.resource) || a.action.localeCompare(b.action);
		return {
			agentId,
			window: { since: window.since ?? null, until: window.until ?? null },
			granted: atoms,
			grants,
			used: usedOut,
			unused,
			attemptedOnly,
			deniedNoGrant: [...denied.values()].sort(sortPair),
			uncovered: [...uncovered.values()].sort(sortPair),
			evidence: { ...ev },
		};
	}

	return { add, finish };
}

/**
 * Compare what an agent is granted with what it actually did. Reads decision rows in pages, so a long window does not load into memory at once.
 * Permissions are split to one action each, so "read and write on X" shows up as two entries and only the unused half is flagged. Only allowed rows count as use. A denial for another cause (rate limit, time window, approval, revoked agent) never counts as evidence that a grant is unused.
 */
export async function analyzeUsage(
	db: Database,
	agentId: string,
	opts: AnalyzeOptions = {},
): Promise<UsageAnalysis> {
	const grants = await loadGrants(db, agentId);
	const acc = createUsageAccumulator(agentId, grants, opts);
	for await (const page of readDecisionRows(db, agentId, opts)) {
		for (const row of page) acc.add(row);
	}
	return acc.finish();
}
