/** Edge cases for policy shrink: empty and unicode resources, NaN options, duplicate atoms, paging. */

import { describe, expect, it } from "vitest";
import type { Database } from "../src/db/database.js";
import { classifyRow } from "../src/policy-shrink/permissions.js";
import { readDecisionRows } from "../src/policy-shrink/rows.js";
import { suggestShrink } from "../src/policy-shrink/shrink.js";
import type { DecisionRow, UsageAnalysis } from "../src/policy-shrink/types.js";
import { createReplay, verifyShrink } from "../src/policy-shrink/verify.js";
import type { Permission } from "../src/types.js";

const T = new Date("2026-10-01T00:00:00Z");

function analysis(
	granted: Permission[],
	used: Array<{ permission: Permission; count: number }>,
	extra: Partial<UsageAnalysis> = {},
): UsageAnalysis {
	return {
		agentId: "a1",
		window: { since: null, until: null },
		granted,
		grants: granted.map((permission) => ({ permission, source: { kind: "own" } })),
		used: used.map((u) => ({
			permission: u.permission,
			count: u.count,
			firstSeen: T,
			lastSeen: T,
			via: [],
		})),
		unused: [],
		attemptedOnly: [],
		deniedNoGrant: [],
		uncovered: [],
		evidence: {
			rowsScanned: 0,
			allowedRows: 0,
			noGrantDenials: 0,
			otherDenials: 0,
			internalRows: 0,
			uncoveredAllows: 0,
		},
		...extra,
	};
}

function row(
	id: string,
	resource: string,
	result: DecisionRow["result"] = "allowed",
	reason: string | null = null,
): DecisionRow {
	return { id, action: "read", resource, result, reason, timestamp: T };
}

/** A fake Database whose query builder records each limit() call and returns no rows. */
function fakeDb(limits: unknown[]): Database {
	const query = {
		from: () => query,
		where: () => query,
		orderBy: () => query,
		limit: (n: unknown) => {
			limits.push(n);
			return Promise.resolve([]);
		},
	};
	return { select: () => query } as unknown as Database;
}

describe("policy-shrink edge cases", () => {
	it("treats empty and unicode resources as plain strings", () => {
		const granted: Permission[] = [
			{ resource: "", actions: ["read"] },
			{ resource: "tool:été", actions: ["read"] },
		];
		const out = suggestShrink(
			analysis(granted, [
				{ permission: granted[0] as Permission, count: 1 },
				{ permission: granted[1] as Permission, count: 1 },
			]),
			{ generalize: true },
		);
		expect(out.keep).toHaveLength(2);
		expect(out.remove).toEqual([]);
		expect(out.rewrites).toEqual([]);
	});

	it("removes a grant that was never used and keeps the one that was", () => {
		const a: Permission = { resource: "tool:a", actions: ["read"] };
		const b: Permission = { resource: "tool:b", actions: ["read"] };
		const out = suggestShrink(analysis([a, b], [{ permission: a, count: 1 }]));
		expect(out.keep).toEqual([a]);
		expect(out.remove).toEqual([b]);
	});

	it("keeps a grant whose only traffic was denied for another cause", () => {
		const a: Permission = { resource: "tool:a", actions: ["read"] };
		const out = suggestShrink(analysis([a], [], { attemptedOnly: [a] }), { minObservations: 5 });
		expect(out.keep).toEqual([a]);
		expect(out.remove).toEqual([]);
	});

	it("classifies a denial with no reason as another cause, not a missing grant", () => {
		expect(classifyRow(row("1", "tool:a", "denied", null))).toBe("deny_other");
		expect(classifyRow(row("2", "tool:a", "denied", "no permission grants matched"))).toBe(
			"deny_other",
		);
		expect(classifyRow(row("3", "tool:a", "denied", "No permission grants"))).toBe("deny_no_grant");
	});

	it("gives the same counts whatever order rows with equal timestamps arrive in", () => {
		const proposed: Permission[] = [{ resource: "tool:a", actions: ["read"] }];
		const rows = [
			row("r2", "tool:a"),
			row("r1", "tool:b"),
			row("r3", "tool:a", "denied", "No permission grants"),
		];
		const forward = verifyShrink(rows, proposed);
		const backward = verifyShrink([...rows].reverse(), proposed);
		expect(backward.replayedAllows).toBe(forward.replayedAllows);
		expect(backward.stillAllowed).toBe(forward.stillAllowed);
		expect(backward.newlyDeniedCount).toBe(forward.newlyDeniedCount);
		expect(backward.wouldAlsoAllowCount).toBe(forward.wouldAlsoAllowCount);
	});

	it("counts exactly and reports truncation when the example cap is zero", () => {
		const report = verifyShrink([row("1", "tool:a"), row("2", "tool:b")], [], {
			maxExamples: 0,
		});
		expect(report.newlyDeniedCount).toBe(2);
		expect(report.newlyDenied).toEqual([]);
		expect(report.truncated).toBe(true);
	});

	it("admits nested resources under a wildcard proposal without flagging them", () => {
		const proposed: Permission[] = [{ resource: "tool:*", actions: ["read"] }];
		const replay = createReplay(proposed);
		replay.add(row("1", "tool:a"));
		replay.add(row("2", "tool:b/nested"));
		const report = replay.finish();
		expect(report.newlyDeniedCount).toBe(0);
		expect(report.stillAllowed).toBe(2);
	});

	it("reads pages with a fractional size as whole numbers", async () => {
		const limits: unknown[] = [];
		for await (const _page of readDecisionRows(fakeDb(limits), "a1", { pageSize: 2.7 })) {
		}
		expect(limits).toEqual([2]);
	});

	it("clamps a NaN page size to a positive integer", async () => {
		// A NaN page size must not reach LIMIT.
		const limits: unknown[] = [];
		for await (const _page of readDecisionRows(fakeDb(limits), "a1", { pageSize: Number.NaN })) {
		}
		expect(Number.isSafeInteger(limits[0]) && (limits[0] as number) >= 1).toBe(true);
	});

	it("never merges a single sibling when generalizeMin is NaN (an unset env var)", () => {
		// A NaN minimum falls back to the default instead of skipping the guard.
		const a: Permission = { resource: "tool:a", actions: ["read"] };
		const star: Permission = { resource: "tool:*", actions: ["read"] };
		const out = suggestShrink(analysis([star, a], [{ permission: a, count: 5 }]), {
			generalize: true,
			generalizeMin: Number.NaN,
		});
		expect(out.rewrites).toEqual([]);
	});

	it("counts distinct resources for generalizeMin, not duplicate atoms", () => {
		// Duplicates in a hand-built analysis must not count as siblings.
		const a: Permission = { resource: "tool:a", actions: ["read"] };
		const star: Permission = { resource: "tool:*", actions: ["read"] };
		const out = suggestShrink(
			analysis([star, a, { ...a }, { ...a }], [{ permission: a, count: 5 }]),
			{ generalize: true, generalizeMin: 3 },
		);
		expect(out.rewrites).toEqual([]);
	});

	it("keeps a used grant when minObservations is NaN", () => {
		const a: Permission = { resource: "tool:a", actions: ["read"] };
		const out = suggestShrink(analysis([a], [{ permission: a, count: 5 }]), {
			minObservations: Number.NaN,
		});
		expect(out.keep).toEqual([a]);
	});

	it("lists examples with a NaN maxExamples the same as the default", () => {
		const report = verifyShrink([row("1", "tool:a")], [], { maxExamples: Number.NaN });
		expect(report.newlyDenied).toHaveLength(1);
		expect(report.truncated).toBe(false);
	});
});
