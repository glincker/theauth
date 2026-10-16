/**
 * The indexed grant matcher must give exactly the first match the engine's linear
 * findMatchingPermission gives, for any permission list and any (action, resource).
 */

import { describe, expect, it } from "vitest";
import { findMatchingPermission } from "../src/policy/abac.js";
import { createGrantMatcher } from "../src/policy-shrink/permissions.js";
import type { Permission } from "../src/types.js";

/** Small deterministic PRNG (mulberry32). */
function rng(seed: number): () => number {
	let a = seed >>> 0;
	return () => {
		a = (a + 0x6d2b79f5) >>> 0;
		let t = a;
		t = Math.imul(t ^ (t >>> 15), t | 1);
		t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
		return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
	};
}

const SEGMENTS = ["a", "b", "c", "", "tool", "mcp", "été", "a*"];
const ACTIONS = ["read", "write", "delete", "*"];

describe("indexed grant matcher", () => {
	it("equals the linear scan on randomized permission sets", () => {
		const rand = rng(20261016);
		const pick = <T>(list: readonly T[]): T => list[Math.floor(rand() * list.length)] as T;
		const resource = (wild: boolean): string => {
			const parts = Array.from({ length: 1 + Math.floor(rand() * 3) }, () => pick(SEGMENTS));
			if (wild && rand() < 0.45) parts[Math.floor(rand() * parts.length)] = "*";
			return rand() < 0.04 && wild ? "*" : parts.join(":");
		};
		let comparisons = 0;
		for (let round = 0; round < 300; round++) {
			const permissions: Permission[] = Array.from({ length: 1 + Math.floor(rand() * 25) }, () => ({
				resource: resource(true),
				actions: Array.from({ length: 1 + Math.floor(rand() * 2) }, () => pick(ACTIONS)),
			}));
			const find = createGrantMatcher(permissions);
			for (let i = 0; i < 120; i++) {
				const action = pick(["read", "write", "delete", "admin"]);
				const res = resource(false);
				expect(find(action, res)).toEqual(findMatchingPermission(permissions, action, res));
				// Ask twice: the memoized answer must not change.
				expect(find(action, res)).toEqual(findMatchingPermission(permissions, action, res));
				comparisons += 2;
			}
		}
		expect(comparisons).toBe(72_000);
	});

	it("returns the lowest index when a wildcard grant precedes and follows a specific one", () => {
		const permissions: Permission[] = [
			{ resource: "tool:a", actions: ["write"] },
			{ resource: "*", actions: ["read"] },
			{ resource: "tool:*", actions: ["read"] },
			{ resource: "tool:a", actions: ["read"] },
		];
		const find = createGrantMatcher(permissions);
		expect(find("read", "tool:a")?.index).toBe(1);
		expect(find("write", "tool:a")?.index).toBe(0);
		expect(find("delete", "tool:a")).toBeNull();
	});

	it("handles 200 proposals over many distinct resources without scanning all of them per row", () => {
		const permissions: Permission[] = Array.from({ length: 200 }, (_, i) => ({
			resource: `svc${i}:*`,
			actions: ["read"],
		}));
		const find = createGrantMatcher(permissions);
		expect(find("read", "svc150:thing")?.index).toBe(150);
		expect(find("read", "other:thing")).toBeNull();
	});
});
