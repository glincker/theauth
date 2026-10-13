/**
 * A SCIM client controls the PATCH path and value. Neither may reach
 * Object.prototype or a prototype chain.
 */

import { afterEach, describe, expect, it } from "vitest";
import { applyPatchOps, parsePatchPath, ScimPatchError } from "../src/auth/scim-patch.js";

function leaked(): unknown {
	return (Object.prototype as Record<string, unknown>).polluted;
}

afterEach(() => {
	// If a test did pollute, do not poison the other suites in this worker.
	Reflect.deleteProperty(Object.prototype, "polluted");
});

describe("SCIM PATCH prototype pollution", () => {
	const hostile = [
		"__proto__.polluted",
		"name.__proto__.polluted",
		"constructor.prototype.polluted",
		'emails[type eq "work"].__proto__.polluted',
		"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:__proto__.polluted",
		"prototype.polluted",
	];

	it.each(hostile)("rejects the path %s", (path) => {
		expect(() => parsePatchPath(path)).toThrow(ScimPatchError);
	});

	it.each(hostile)("applyPatchOps does not pollute for %s", (path) => {
		const resource: Record<string, unknown> = { userName: "a", emails: [{ type: "work" }] };
		try {
			applyPatchOps(resource, [{ op: "add", path, value: "yes" }]);
		} catch (err) {
			expect(err).toBeInstanceOf(ScimPatchError);
		}
		expect(leaked()).toBeUndefined();
		expect(({} as Record<string, unknown>).polluted).toBeUndefined();
	});

	it("rejects an unsafe key in a pathless value object", () => {
		const value = JSON.parse('{"__proto__": {"polluted": "yes"}}') as Record<string, unknown>;
		const resource: Record<string, unknown> = { userName: "a" };
		expect(() => applyPatchOps(resource, [{ op: "add", value }])).toThrow(ScimPatchError);
		expect(leaked()).toBeUndefined();
	});

	it("still accepts ordinary nested paths", () => {
		const resource: Record<string, unknown> = { name: { givenName: "a" } };
		applyPatchOps(resource, [{ op: "replace", path: "name.familyName", value: "b" }]);
		expect(resource.name).toEqual({ givenName: "a", familyName: "b" });
	});
});
