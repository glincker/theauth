import { describe, expect, it } from "vitest";
import { decodePathname, secretsMatch } from "../src/dashboard-server.js";

describe("dashboard server path and secret handling", () => {
	it("decodes an ordinary path", () => {
		expect(decodePathname("/assets/app%20one.js")).toBe("/assets/app one.js");
	});

	it("returns null for a malformed escape instead of throwing", () => {
		expect(decodePathname("/%E0%A4%A")).toBeNull();
		expect(decodePathname("/%")).toBeNull();
	});

	it("returns null for an embedded NUL byte", () => {
		expect(decodePathname("/assets/app.js%00.png")).toBeNull();
	});

	it("compares secrets by value and by length", () => {
		expect(secretsMatch("s3cret", "s3cret")).toBe(true);
		expect(secretsMatch("s3cret", "s3cret!")).toBe(false);
		expect(secretsMatch("", "s3cret")).toBe(false);
		expect(secretsMatch("S3cret", "s3cret")).toBe(false);
	});
});
