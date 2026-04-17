/**
 * Tests for the policy decision combiner.
 *
 * Covers deny-overrides (default) and permit-overrides strategies, empty
 * input, and field passthrough from the winning partial.
 */

import { describe, expect, it } from "vitest";
import type { PartialDecision } from "../src/policy/combiner.js";
import { combine } from "../src/policy/combiner.js";
import { POLICY_ERROR_CODES } from "../src/policy/types.js";

// ---------------------------------------------------------------------------
// deny-overrides (default strategy)
// ---------------------------------------------------------------------------

describe("combine — deny-overrides", () => {
	it("empty array returns indeterminate with allowed=false", () => {
		const result = combine([]);
		expect(result.allowed).toBe(false);
		expect(result.effect).toBe("indeterminate");
		expect(result.reason).toBe(POLICY_ERROR_CODES.NO_MATCHING_PERMISSION);
	});

	it("single permit returns permit", () => {
		const partial: PartialDecision = {
			effect: "permit",
			reason: "read allowed",
			matchedPermissionId: "perm-1",
		};
		const result = combine([partial]);
		expect(result.allowed).toBe(true);
		expect(result.effect).toBe("permit");
		expect(result.reason).toBe("read allowed");
	});

	it("single deny returns deny", () => {
		const partial: PartialDecision = {
			effect: "deny",
			reason: "ip blocked",
			matchedPermissionId: "perm-2",
		};
		const result = combine([partial]);
		expect(result.allowed).toBe(false);
		expect(result.effect).toBe("deny");
		expect(result.reason).toBe("ip blocked");
	});

	it("mixed [permit, deny] returns deny (deny wins regardless of order)", () => {
		const partials: PartialDecision[] = [
			{ effect: "permit", reason: "permit first", matchedPermissionId: "perm-1" },
			{ effect: "deny", reason: "deny second", matchedPermissionId: "perm-2" },
		];
		const result = combine(partials);
		expect(result.allowed).toBe(false);
		expect(result.effect).toBe("deny");
		expect(result.reason).toBe("deny second");
	});

	it("mixed [deny, permit] returns deny", () => {
		const partials: PartialDecision[] = [
			{ effect: "deny", reason: "deny first", matchedPermissionId: "perm-1" },
			{ effect: "permit", reason: "permit second", matchedPermissionId: "perm-2" },
		];
		const result = combine(partials);
		expect(result.allowed).toBe(false);
		expect(result.effect).toBe("deny");
		expect(result.reason).toBe("deny first");
	});

	it("multiple permits returns the first permit's reason and matchedPermissionId", () => {
		const partials: PartialDecision[] = [
			{ effect: "permit", reason: "first permit", matchedPermissionId: "perm-1" },
			{ effect: "permit", reason: "second permit", matchedPermissionId: "perm-2" },
		];
		const result = combine(partials);
		expect(result.allowed).toBe(true);
		expect(result.effect).toBe("permit");
		expect(result.reason).toBe("first permit");
		expect(result.matchedPermissionId).toBe("perm-1");
	});

	it("multiple denies returns the first deny", () => {
		const partials: PartialDecision[] = [
			{ effect: "deny", reason: "first deny", matchedPermissionId: "perm-1" },
			{ effect: "deny", reason: "second deny", matchedPermissionId: "perm-2" },
		];
		const result = combine(partials);
		expect(result.allowed).toBe(false);
		expect(result.effect).toBe("deny");
		expect(result.reason).toBe("first deny");
		expect(result.matchedPermissionId).toBe("perm-1");
	});
});

// ---------------------------------------------------------------------------
// permit-overrides
// ---------------------------------------------------------------------------

describe("combine — permit-overrides", () => {
	it("mixed [permit, deny] returns permit", () => {
		const partials: PartialDecision[] = [
			{ effect: "deny", reason: "deny first", matchedPermissionId: "perm-1" },
			{ effect: "permit", reason: "permit second", matchedPermissionId: "perm-2" },
		];
		const result = combine(partials, "permit-overrides");
		expect(result.allowed).toBe(true);
		expect(result.effect).toBe("permit");
		expect(result.reason).toBe("permit second");
	});

	it("single deny with no permits returns deny", () => {
		const partial: PartialDecision = {
			effect: "deny",
			reason: "blocked",
			matchedPermissionId: "perm-1",
		};
		const result = combine([partial], "permit-overrides");
		expect(result.allowed).toBe(false);
		expect(result.effect).toBe("deny");
		expect(result.reason).toBe("blocked");
	});

	it("empty array returns indeterminate", () => {
		const result = combine([], "permit-overrides");
		expect(result.allowed).toBe(false);
		expect(result.effect).toBe("indeterminate");
		expect(result.reason).toBe(POLICY_ERROR_CODES.NO_MATCHING_PERMISSION);
	});
});

// ---------------------------------------------------------------------------
// Field passthrough
// ---------------------------------------------------------------------------

describe("combine — field passthrough", () => {
	it("matchedPermissionId from winning partial appears on result", () => {
		const partial: PartialDecision = {
			effect: "permit",
			reason: "allowed",
			matchedPermissionId: "perm-abc",
		};
		const result = combine([partial]);
		expect(result.matchedPermissionId).toBe("perm-abc");
	});

	it("matchedRelation from winning partial appears on result", () => {
		const partial: PartialDecision = {
			effect: "permit",
			reason: "owner relation",
			matchedPermissionId: "perm-xyz",
			matchedRelation: "owner",
		};
		const result = combine([partial]);
		expect(result.matchedRelation).toBe("owner");
	});

	it("matchedRelation from winning deny appears on result", () => {
		const partials: PartialDecision[] = [
			{ effect: "permit", reason: "permit", matchedPermissionId: "perm-1" },
			{
				effect: "deny",
				reason: "deny",
				matchedPermissionId: "perm-2",
				matchedRelation: "viewer",
			},
		];
		const result = combine(partials, "deny-overrides");
		expect(result.matchedRelation).toBe("viewer");
		expect(result.matchedPermissionId).toBe("perm-2");
	});
});
