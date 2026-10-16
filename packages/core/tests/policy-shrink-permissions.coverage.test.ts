/**
 * Permission keys, splitting and the grant matcher's memo limit.
 */

import { describe, expect, it } from "vitest";
import {
	createGrantMatcher,
	extrasKey,
	splitPermission,
} from "../src/policy-shrink/permissions.js";
import type { Permission } from "../src/types.js";

describe("extrasKey", () => {
	it("ignores key order inside nested constraint objects and arrays", () => {
		const a: Permission = {
			resource: "doc:*",
			actions: ["read"],
			constraints: { list: [{ b: 1, a: 2 }], nested: { y: true, x: false } },
		} as Permission;
		const b: Permission = {
			resource: "doc:*",
			actions: ["read"],
			constraints: { nested: { x: false, y: true }, list: [{ a: 2, b: 1 }] },
		} as Permission;
		expect(extrasKey(a)).toBe(extrasKey(b));
	});

	it("tells apart constraints that differ inside an array", () => {
		const a = {
			resource: "doc:*",
			actions: ["read"],
			constraints: { list: [{ a: 2 }] },
		} as Permission;
		const b = {
			resource: "doc:*",
			actions: ["read"],
			constraints: { list: [{ a: 3 }] },
		} as Permission;
		expect(extrasKey(a)).not.toBe(extrasKey(b));
	});

	it("keys an undefined constraint value the same as null", () => {
		const withUndefined = {
			resource: "doc:*",
			actions: ["read"],
			constraints: { ip: undefined },
		} as unknown as Permission;
		const withNull = {
			resource: "doc:*",
			actions: ["read"],
			constraints: { ip: null },
		} as unknown as Permission;
		expect(extrasKey(withUndefined)).toBe(extrasKey(withNull));
	});
});

describe("splitPermission", () => {
	it("keeps constraints and relation on every single-action piece and drops duplicate actions", () => {
		const pieces = splitPermission({
			resource: "doc:1",
			actions: ["read", "write", "read"],
			constraints: { ip: ["10.0.0.1"] },
			relation: "owner",
		} as Permission);
		expect(pieces).toEqual([
			{
				resource: "doc:1",
				actions: ["read"],
				constraints: { ip: ["10.0.0.1"] },
				relation: "owner",
			},
			{
				resource: "doc:1",
				actions: ["write"],
				constraints: { ip: ["10.0.0.1"] },
				relation: "owner",
			},
		]);
	});

	it("omits constraints and relation when the source has none", () => {
		expect(splitPermission({ resource: "doc:1", actions: ["read"] })).toEqual([
			{ resource: "doc:1", actions: ["read"] },
		]);
	});
});

describe("createGrantMatcher memo limit", () => {
	it("keeps answering correctly after the memo is cleared", () => {
		const match = createGrantMatcher([
			{ resource: "doc:*", actions: ["read"] },
			{ resource: "*", actions: ["write"] },
		]);
		// More distinct questions than the memo holds, so it is cleared at least once.
		for (let i = 0; i < 10_050; i++) {
			expect(match("read", `doc:${i}`)?.index).toBe(0);
		}
		expect(match("read", "doc:5")?.index).toBe(0);
		expect(match("write", "other:9")?.index).toBe(1);
		expect(match("delete", "doc:5")).toBeNull();
	});
});
