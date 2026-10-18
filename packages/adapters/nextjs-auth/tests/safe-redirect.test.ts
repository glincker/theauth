import { describe, expect, it } from "vitest";
import { safeRedirectPath } from "../src/safe-redirect.js";

describe("safeRedirectPath", () => {
	it("keeps same-origin paths", () => {
		expect(safeRedirectPath("/app/x?y=1")).toBe("/app/x?y=1");
	});

	it.each([
		"//other.example",
		"https://other.example",
		"/\\other.example",
		"javascript:alert(1)",
		"/ok\r\nSet-Cookie: a=b",
		"",
		null,
		undefined,
	])("falls back for %s", (input) => {
		expect(safeRedirectPath(input, "/home")).toBe("/home");
	});
});
