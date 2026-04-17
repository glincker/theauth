import { describe, expect, it } from "vitest";
import { applyPatchOps, parsePatchPath, ScimPatchError } from "../src/auth/scim-patch.js";

function buildUser() {
	return {
		schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
		id: "abc-123",
		userName: "bjensen",
		name: { givenName: "Barbara", familyName: "Jensen" },
		emails: [
			{ value: "bjensen@example.com", type: "work", primary: true },
			{ value: "barb@home.example", type: "home" },
		],
		active: true,
		meta: {
			resourceType: "User",
			created: "2026-01-01T00:00:00Z",
			lastModified: "2026-01-01T00:00:00Z",
		},
	};
}

describe("parsePatchPath", () => {
	it("parses a plain attribute", () => {
		const p = parsePatchPath("displayName");
		expect(p.base).toBe("displayName");
		expect(p.valueFilter).toBeUndefined();
		expect(p.subPath).toBeUndefined();
	});

	it("parses a dotted sub-attribute", () => {
		const p = parsePatchPath("name.givenName");
		expect(p.base).toBe("name");
		expect(p.subPath).toEqual(["givenName"]);
	});

	it("parses a value-filter selector", () => {
		const p = parsePatchPath('emails[type eq "work"]');
		expect(p.base).toBe("emails");
		expect(p.valueFilter).toBeDefined();
		expect(p.subPath).toBeUndefined();
	});

	it("parses value filter plus sub-path", () => {
		const p = parsePatchPath('emails[type eq "work"].value');
		expect(p.base).toBe("emails");
		expect(p.valueFilter).toBeDefined();
		expect(p.subPath).toEqual(["value"]);
	});

	it("parses URN-prefixed attribute paths", () => {
		const p = parsePatchPath(
			"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department",
		);
		expect(p.schemaUrn).toBe("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User");
		expect(p.base).toBe("department");
	});

	it("rejects an empty string", () => {
		expect(() => parsePatchPath("")).toThrow(ScimPatchError);
	});

	it("rejects unbalanced brackets", () => {
		expect(() => parsePatchPath('emails[type eq "work"')).toThrow(ScimPatchError);
	});

	it("rejects invalid inner filter", () => {
		expect(() => parsePatchPath("emails[not-a-filter]")).toThrow(ScimPatchError);
	});
});

describe("applyPatchOps: replace without path", () => {
	it("merges top-level attributes", () => {
		const user = buildUser();
		applyPatchOps(user, [{ op: "replace", value: { displayName: "Barb J", active: false } }]);
		expect(user).toMatchObject({ displayName: "Barb J", active: false });
	});

	it("rejects mutation of id", () => {
		const user = buildUser();
		expect(() => applyPatchOps(user, [{ op: "replace", value: { id: "tampered" } }])).toThrow(
			ScimPatchError,
		);
	});
});

describe("applyPatchOps: simple paths", () => {
	it("replaces a top-level attribute", () => {
		const user = buildUser();
		applyPatchOps(user, [{ op: "replace", path: "active", value: false }]);
		expect(user.active).toBe(false);
	});

	it("replaces a nested attribute", () => {
		const user = buildUser();
		applyPatchOps(user, [{ op: "replace", path: "name.givenName", value: "Barbara-Ann" }]);
		expect(user.name.givenName).toBe("Barbara-Ann");
	});

	it("rejects replacing an immutable attribute via path", () => {
		const user = buildUser();
		expect(() => applyPatchOps(user, [{ op: "replace", path: "id", value: "x" }])).toThrow(
			ScimPatchError,
		);
	});

	it("removes a simple attribute", () => {
		const user = buildUser();
		applyPatchOps(user, [{ op: "remove", path: "active" }]);
		expect(user.active).toBeUndefined();
	});
});

describe("applyPatchOps: value-filter selectors", () => {
	it("replaces the matching element's sub-attribute", () => {
		const user = buildUser();
		applyPatchOps(user, [
			{ op: "replace", path: 'emails[type eq "work"].value', value: "new@example.com" },
		]);
		const workEmail = user.emails.find((e) => e.type === "work");
		expect(workEmail?.value).toBe("new@example.com");
	});

	it("merges an object onto the matching element", () => {
		const user = buildUser();
		applyPatchOps(user, [
			{ op: "replace", path: 'emails[type eq "work"]', value: { primary: false } },
		]);
		const workEmail = user.emails.find((e) => e.type === "work");
		expect(workEmail?.primary).toBe(false);
	});

	it("removes matching elements", () => {
		const user = buildUser();
		applyPatchOps(user, [{ op: "remove", path: 'emails[type eq "home"]' }]);
		expect(user.emails.every((e) => e.type !== "home")).toBe(true);
	});

	it("is a no-op when no element matches", () => {
		const user = buildUser();
		applyPatchOps(user, [{ op: "replace", path: 'emails[type eq "other"].value', value: "x" }]);
		expect(user.emails).toHaveLength(2);
	});
});

describe("applyPatchOps: add semantics", () => {
	it("appends to a multi-valued attribute when op=add", () => {
		const user = buildUser();
		applyPatchOps(user, [
			{
				op: "add",
				path: "emails",
				value: [{ value: "extra@example.com", type: "other" }],
			},
		]);
		expect(user.emails.map((e) => e.type)).toContain("other");
		expect(user.emails).toHaveLength(3);
	});

	it("appends via no-path add with multi-valued attrs", () => {
		const user = buildUser();
		applyPatchOps(user, [
			{
				op: "add",
				value: { emails: [{ value: "extra@example.com", type: "other" }] },
			},
		]);
		expect(user.emails).toHaveLength(3);
	});
});

describe("applyPatchOps: extension schemas", () => {
	it("sets an enterprise extension attribute under its URN container", () => {
		const user: Record<string, unknown> = buildUser();
		applyPatchOps(user, [
			{
				op: "replace",
				path: "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department",
				value: "Engineering",
			},
		]);
		const ext = user["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"] as Record<
			string,
			unknown
		>;
		expect(ext.department).toBe("Engineering");
	});
});

describe("applyPatchOps: DoS guardrails", () => {
	it("throws when operation count exceeds the cap", () => {
		const user = buildUser();
		const ops = Array.from({ length: 5 }, () => ({
			op: "replace" as const,
			path: "active",
			value: false,
		}));
		expect(() => applyPatchOps(user, ops, { maxOperations: 4 })).toThrow(ScimPatchError);
	});

	it("honors caller-provided readonly paths", () => {
		const user = buildUser();
		expect(() =>
			applyPatchOps(user, [{ op: "replace", path: "userName", value: "changed" }], {
				readonlyPaths: ["username"],
			}),
		).toThrow(ScimPatchError);
	});
});

describe("applyPatchOps: error mapping", () => {
	it("unknown op throws invalidValue", () => {
		const user = buildUser();
		try {
			applyPatchOps(user, [{ op: "noop" as unknown as "replace", path: "active", value: false }]);
			expect.fail("should have thrown");
		} catch (err) {
			expect(err).toBeInstanceOf(ScimPatchError);
			expect((err as ScimPatchError).scimType).toBe("invalidValue");
		}
	});

	it("remove without path throws noTarget", () => {
		const user = buildUser();
		try {
			applyPatchOps(user, [{ op: "remove" }]);
			expect.fail("should have thrown");
		} catch (err) {
			expect((err as ScimPatchError).scimType).toBe("noTarget");
		}
	});
});
