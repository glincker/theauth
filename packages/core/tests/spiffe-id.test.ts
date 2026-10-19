import { describe, expect, it } from "vitest";
import { parseSpiffeId, parseTrustDomain } from "../src/device/spiffe/spiffe-id.js";

describe("SPIFFE ID (SPIFFE-ID.md section 2)", () => {
	it("accepts the examples of the specification", () => {
		for (const id of [
			"spiffe://trust-domain-name/path",
			"spiffe://k8s-west.example.com/ns/staging/sa/default",
			"spiffe://example.com/9eebccd2-12bf-40a6-b262-65fe0487d453",
			"spiffe://example.org",
		]) {
			expect(parseSpiffeId(id).ok, id).toBe(true);
		}
		const parsed = parseSpiffeId("spiffe://k8s-west.example.com/ns/staging/sa/default");
		expect(parsed).toMatchObject({
			ok: true,
			trustDomain: "k8s-west.example.com",
			path: "/ns/staging/sa/default",
		});
	});

	it("refuses what section 2 forbids", () => {
		const bad = [
			"https://example.org/a",
			"SPIFFE://example.org/a",
			"spiffe:///a",
			"spiffe://",
			"spiffe://Example.org/a",
			"spiffe://user@example.org/a",
			"spiffe://example.org:8080/a",
			"spiffe://exa%6dple.org/a",
			"spiffe://example.org/a?x=1",
			"spiffe://example.org/a#frag",
			"spiffe://example.org/a/",
			"spiffe://example.org//a",
			"spiffe://example.org/./a",
			"spiffe://example.org/a/../b",
			"spiffe://example.org/a%2fb",
			"spiffe://example.org/a b",
			"spiffe://example.org/café",
			"spiffe://[::1]/a",
			`spiffe://example.org/${"a".repeat(2048)}`,
		];
		for (const id of bad) expect(parseSpiffeId(id).ok, id).toBe(false);
	});

	it("accepts an id of exactly 2048 bytes and refuses 2049", () => {
		const base = "spiffe://example.org/";
		expect(parseSpiffeId(base + "a".repeat(2048 - base.length)).ok).toBe(true);
		expect(parseSpiffeId(base + "a".repeat(2049 - base.length)).ok).toBe(false);
	});

	it("parses trust domain names", () => {
		expect(parseTrustDomain("example.org")).toBe("example.org");
		expect(parseTrustDomain("spiffe://example.org")).toBe("example.org");
		expect(parseTrustDomain("spiffe://example.org/path")).toBeNull();
		expect(parseTrustDomain("Example.org")).toBeNull();
	});
});
