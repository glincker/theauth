import { describe, expect, it } from "vitest";
import type { DecisionRow, Grant } from "../src/policy-shrink/index.js";
import {
	classifyRow,
	compactPermissions,
	covers,
	createUsageAccumulator,
	splitPermission,
	suggestShrink,
	verifyShrink,
} from "../src/policy-shrink/index.js";
import type { Permission } from "../src/types.js";

const T0 = new Date("2026-10-01T00:00:00Z");
const NO_GRANT = 'No permission grants agent "a" access to "x" on "y"';

let seq = 0;
function row(
	action: string,
	resource: string,
	result: DecisionRow["result"] = "allowed",
	extra: Partial<DecisionRow> = {},
): DecisionRow {
	seq++;
	return {
		id: `r${seq}`,
		action,
		resource,
		result,
		reason: result === "allowed" ? null : (extra.reason ?? null),
		timestamp: new Date(T0.getTime() + seq * 1000),
		...extra,
	};
}

function grantsOf(perms: Permission[]): Grant[] {
	return perms.flatMap(splitPermission).map((permission) => ({
		permission,
		source: { kind: "own" as const },
	}));
}

function analyze(perms: Permission[], rows: DecisionRow[]) {
	const acc = createUsageAccumulator("a", grantsOf(perms));
	for (const r of rows) acc.add(r);
	return acc.finish();
}

describe("classifyRow", () => {
	it("separates allows, no-grant denials, other denials and bookkeeping", () => {
		expect(classifyRow(row("read", "x"))).toBe("allow");
		expect(classifyRow(row("read", "x", "denied", { reason: NO_GRANT }))).toBe("deny_no_grant");
		expect(
			classifyRow(row("read", "x", "denied", { reason: "POLICY_NO_MATCHING_PERMISSION" })),
		).toBe("deny_no_grant");
		expect(classifyRow(row("read", "x", "denied", { reason: "Rate limit exceeded" }))).toBe(
			"deny_other",
		);
		expect(classifyRow(row("read", "x", "rate_limited"))).toBe("deny_other");
		expect(classifyRow(row("read", "x", "denied"))).toBe("deny_other");
		expect(classifyRow(row("audit.checkpoint", "x"))).toBe("internal");
		expect(classifyRow(row("agent.cascade.revoked", "x"))).toBe("internal");
	});
});

describe("analysis (pure)", () => {
	it("handles no rows: everything granted is unused", () => {
		const a = analyze([{ resource: "tool:a", actions: ["read", "write"] }], []);
		expect(a.used).toEqual([]);
		expect(a.unused).toHaveLength(2);
		expect(a.evidence.rowsScanned).toBe(0);
		expect(suggestShrink(a)).toEqual({
			keep: [],
			remove: [{ resource: "tool:a", actions: ["read", "write"] }],
			rewrites: [],
		});
	});

	it("counts allowed rows per grant with first and last seen", () => {
		const r1 = row("read", "tool:a");
		const r2 = row("read", "tool:a");
		const a = analyze(
			[
				{ resource: "tool:a", actions: ["read", "write"] },
				{ resource: "tool:b", actions: ["read"] },
			],
			[r2, r1],
		);
		expect(a.used).toHaveLength(1);
		expect(a.used[0]).toMatchObject({
			permission: { resource: "tool:a", actions: ["read"] },
			count: 2,
			firstSeen: r1.timestamp,
			lastSeen: r2.timestamp,
		});
		expect(a.unused.map((p) => `${p.resource}:${p.actions[0]}`)).toEqual([
			"tool:a:write",
			"tool:b:read",
		]);
	});

	it("attributes with the engine's first-match rule over wildcards", () => {
		const a = analyze(
			[
				{ resource: "mcp:github:*", actions: ["*"] },
				{ resource: "mcp:github:repos", actions: ["read"] },
			],
			[row("read", "mcp:github:repos"), row("delete", "mcp:github:issues")],
		);
		expect(a.used.map((u) => `${u.permission.resource}/${u.permission.actions[0]}`)).toEqual([
			"mcp:github:*/*",
		]);
		expect(a.used[0]?.count).toBe(2);
		expect(a.unused).toEqual([{ resource: "mcp:github:repos", actions: ["read"] }]);
	});

	it("does not treat denials for other causes as evidence of non-use", () => {
		const a = analyze(
			[
				{ resource: "tool:limited", actions: ["call"] },
				{ resource: "tool:idle", actions: ["call"] },
			],
			[
				row("call", "tool:limited", "denied", { reason: "Rate limit exceeded" }),
				row("call", "tool:limited", "rate_limited"),
			],
		);
		expect(a.used).toEqual([]);
		expect(a.attemptedOnly).toEqual([{ resource: "tool:limited", actions: ["call"] }]);
		expect(a.unused).toEqual([{ resource: "tool:idle", actions: ["call"] }]);
		const s = suggestShrink(a);
		expect(s.keep).toEqual([{ resource: "tool:limited", actions: ["call"] }]);
		expect(s.remove).toEqual([{ resource: "tool:idle", actions: ["call"] }]);
	});

	it("reports allows no current grant covers (expired or removed grants)", () => {
		const a = analyze(
			[{ resource: "tool:a", actions: ["read"] }],
			[row("read", "tool:gone"), row("read", "tool:gone")],
		);
		expect(a.evidence.uncoveredAllows).toBe(2);
		expect(a.uncovered).toEqual([{ action: "read", resource: "tool:gone", count: 2 }]);
	});

	it("ignores bookkeeping rows", () => {
		const a = analyze([{ resource: "*", actions: ["*"] }], [row("audit.checkpoint", "audit")]);
		expect(a.used).toEqual([]);
		expect(a.evidence.internalRows).toBe(1);
	});

	it("keeps constraints on the kept permission", () => {
		const p: Permission = {
			resource: "tool:a",
			actions: ["read"],
			constraints: { maxCallsPerHour: 5 },
		};
		const a = analyze([p], [row("read", "tool:a")]);
		expect(suggestShrink(a).keep).toEqual([p]);
	});
});

describe("suggestShrink", () => {
	const perms: Permission[] = [
		{ resource: "doc:1", actions: ["read"] },
		{ resource: "doc:2", actions: ["read"] },
		{ resource: "doc:3", actions: ["read"] },
		{ resource: "doc:4", actions: ["read"] },
		{ resource: "*", actions: ["list"] },
		{ resource: "doc:*", actions: ["read"] },
	];

	it("minObservations drops rarely used grants", () => {
		const rows = [row("read", "doc:1"), row("read", "doc:1"), row("read", "doc:2")];
		const a = analyze(perms, rows);
		expect(suggestShrink(a, { minObservations: 1 }).keep).toEqual([
			{ resource: "doc:1", actions: ["read"] },
			{ resource: "doc:2", actions: ["read"] },
		]);
		expect(suggestShrink(a, { minObservations: 2 }).keep).toEqual([
			{ resource: "doc:1", actions: ["read"] },
		]);
	});

	it("does not generalize by default", () => {
		const a = analyze(perms, [row("read", "doc:1"), row("read", "doc:2"), row("read", "doc:3")]);
		expect(suggestShrink(a).rewrites).toEqual([]);
	});

	it("generalizes only observed siblings, only within an existing grant", () => {
		const a = analyze(perms, [row("read", "doc:1"), row("read", "doc:2"), row("read", "doc:3")]);
		const s = suggestShrink(a, { generalize: true });
		expect(s.rewrites).toHaveLength(1);
		expect(s.rewrites[0]?.to).toEqual({ resource: "doc:*", actions: ["read"] });
		expect(s.rewrites[0]?.from.map((p) => p.resource)).toEqual(["doc:1", "doc:2", "doc:3"]);
		expect(s.keep).toEqual([{ resource: "doc:*", actions: ["read"] }]);
	});

	it("does not generalize when no existing grant covers the wildcard", () => {
		const narrow: Permission[] = ["1", "2", "3"].map((n) => ({
			resource: `doc:${n}`,
			actions: ["read"],
		}));
		const a = analyze(
			narrow,
			narrow.map((p) => row("read", p.resource)),
		);
		expect(suggestShrink(a, { generalize: true }).rewrites).toEqual([]);
	});

	it("does not generalize over a resource that was denied for lack of a grant", () => {
		const a = analyze(perms, [
			row("read", "doc:1"),
			row("read", "doc:2"),
			row("read", "doc:3"),
			row("read", "doc:secret", "denied", { reason: NO_GRANT }),
		]);
		expect(suggestShrink(a, { generalize: true }).rewrites).toEqual([]);
	});

	it("needs generalizeMin siblings", () => {
		const a = analyze(perms, [row("read", "doc:1"), row("read", "doc:2")]);
		expect(suggestShrink(a, { generalize: true }).rewrites).toEqual([]);
		expect(suggestShrink(a, { generalize: true, generalizeMin: 2 }).rewrites).toHaveLength(1);
	});

	it("is deterministic", () => {
		const rows = [row("read", "doc:3"), row("read", "doc:1"), row("list", "x:y")];
		const a = analyze(perms, rows);
		expect(JSON.stringify(suggestShrink(a, { generalize: true }))).toBe(
			JSON.stringify(suggestShrink(a, { generalize: true })),
		);
	});
});

describe("verifyShrink", () => {
	it("proves every historical allow is kept and flags what flips", () => {
		const rows = [
			row("read", "doc:1"),
			row("read", "doc:2"),
			row("write", "doc:1", "denied", { reason: NO_GRANT }),
			row("read", "doc:1", "denied", { reason: "Rate limit exceeded" }),
			row("audit.checkpoint", "audit"),
		];
		const ok = verifyShrink(rows, [{ resource: "doc:*", actions: ["read"] }]);
		expect(ok).toMatchObject({
			replayedAllows: 2,
			stillAllowed: 2,
			newlyDeniedCount: 0,
			wouldAlsoAllowCount: 0,
			ignoredRows: 2,
		});
		expect(ok.perPermission[0]?.allows).toBe(2);

		const bad = verifyShrink(rows, [{ resource: "doc:1", actions: ["*"] }]);
		expect(bad.newlyDenied.map((r) => r.resource)).toEqual(["doc:2"]);
		expect(bad.wouldAlsoAllowPreviouslyDenied.map((r) => `${r.action}:${r.resource}`)).toEqual([
			"write:doc:1",
		]);
	});

	it("caps example lists but keeps exact counts", () => {
		const rows = Array.from({ length: 10 }, () => row("read", "gone"));
		const r = verifyShrink(rows, [], { maxExamples: 3 });
		expect(r.newlyDeniedCount).toBe(10);
		expect(r.newlyDenied).toHaveLength(3);
		expect(r.truncated).toBe(true);
	});
});

describe("covers", () => {
	it("uses engine wildcard semantics", () => {
		const p = (resource: string, ...actions: string[]): Permission => ({ resource, actions });
		expect(covers(p("*", "*"), p("a:b", "read"))).toBe(true);
		expect(covers(p("a:*", "read"), p("a:b:*", "read"))).toBe(true);
		expect(covers(p("a:b:*", "read"), p("a:*", "read"))).toBe(false);
		expect(covers(p("a:b", "read"), p("a:b", "read", "write"))).toBe(false);
		expect(covers(p("a:b", "*"), p("a:b", "write"))).toBe(true);
	});
	it("compactPermissions merges actions per resource", () => {
		expect(
			compactPermissions([
				{ resource: "a", actions: ["r"] },
				{ resource: "b", actions: ["r"] },
				{ resource: "a", actions: ["w"] },
			]),
		).toEqual([
			{ resource: "a", actions: ["r", "w"] },
			{ resource: "b", actions: ["r"] },
		]);
	});
});

// Property style checks with a seeded generator, so failures reproduce.
function mulberry32(seed: number): () => number {
	let a = seed;
	return () => {
		a = (a + 0x6d2b79f5) | 0;
		let t = Math.imul(a ^ (a >>> 15), 1 | a);
		t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
		return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
	};
}

const ACTIONS = ["read", "write", "delete"];
const RESOURCES = ["a:x", "a:y", "a:z", "a:w", "b:x", "b:y", "b:z", "c:x"];

describe("properties", () => {
	for (let seed = 1; seed <= 150; seed++) {
		it(`seed ${seed}: shrink never newly denies, never widens`, () => {
			const rnd = mulberry32(seed);
			const pick = <T>(xs: T[]): T => xs[Math.floor(rnd() * xs.length)] as T;
			const grantsList: Permission[] = [];
			const nGrants = 1 + Math.floor(rnd() * 6);
			for (let i = 0; i < nGrants; i++) {
				const resource = rnd() < 0.3 ? pick(["*", "a:*", "b:*"]) : pick(RESOURCES);
				const actions = rnd() < 0.2 ? ["*"] : ACTIONS.filter(() => rnd() < 0.5);
				if (actions.length) grantsList.push({ resource, actions });
			}
			const acc = createUsageAccumulator("a", grantsOf(grantsList));
			const pool = grantsOf(grantsList);
			const rows: DecisionRow[] = [];
			const n = Math.floor(rnd() * 60);
			for (let i = 0; i < n; i++) {
				const action = pick(ACTIONS);
				const resource = pick(RESOURCES);
				const covered = pool.some(
					(g) => verifyShrink([row(action, resource)], [g.permission]).stillAllowed === 1,
				);
				const roll = rnd();
				if (covered && roll < 0.8) rows.push(row(action, resource));
				else if (!covered) rows.push(row(action, resource, "denied", { reason: NO_GRANT }));
				else rows.push(row(action, resource, "denied", { reason: "Rate limit exceeded" }));
			}
			for (const r of rows) acc.add(r);
			const analysis = acc.finish();
			const original = analysis.granted;

			for (const opts of [{}, { generalize: true }, { generalize: true, generalizeMin: 2 }]) {
				const s = suggestShrink(analysis, opts);
				const report = verifyShrink(rows, s.keep);
				expect(report.newlyDeniedCount).toBe(0);
				expect(report.wouldAlsoAllowCount).toBe(0);
				// Never broader than the grants the agent already had.
				for (const k of s.keep) {
					for (const atom of splitPermission(k)) {
						expect(original.some((g) => covers(g, atom))).toBe(true);
					}
				}
				// Every rewrite merged only permissions that were used.
				const usedKeys = new Set(
					analysis.used.map((u) => `${u.permission.resource}|${u.permission.actions[0]}`),
				);
				for (const rw of s.rewrites) {
					for (const f of rw.from) expect(usedKeys.has(`${f.resource}|${f.actions[0]}`)).toBe(true);
				}
				// keep and remove never overlap on an atom.
				const keepAtoms = new Set(
					s.keep.flatMap(splitPermission).map((p) => `${p.resource}|${p.actions[0]}`),
				);
				if (!("generalize" in opts)) {
					for (const rmv of s.remove.flatMap(splitPermission)) {
						expect(keepAtoms.has(`${rmv.resource}|${rmv.actions[0]}`)).toBe(false);
					}
				}
			}
			// Without generalize, keep is a subset of the original atoms.
			const plain = suggestShrink(analysis);
			const origKeys = new Set(original.map((p) => `${p.resource}|${p.actions[0]}`));
			for (const atom of plain.keep.flatMap(splitPermission)) {
				expect(origKeys.has(`${atom.resource}|${atom.actions[0]}`)).toBe(true);
			}
		});
	}
});
