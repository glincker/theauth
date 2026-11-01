/** Regression for GHSA-r79r-x4p9-7q2c: a client-supplied X-Forwarded-For must never decide the client IP. */
import { describe, expect, it } from "vitest";
import { resolveClientIp } from "../src/auth/client-ip.js";

const req = (headers: Record<string, string>) => new Request("http://localhost/x", { headers });

describe("resolveClientIp with forged headers", () => {
	it("returns null by default whatever the headers say", () => {
		expect(resolveClientIp(req({ "x-forwarded-for": "10.0.0.1" }))).toBeNull();
		expect(
			resolveClientIp(req({ "x-forwarded-for": "10.0.0.1" }), { trustedProxyCount: 0 }),
		).toBeNull();
		expect(resolveClientIp(req({ "x-real-ip": "10.0.0.1" }))).toBeNull();
	});

	const cases: Array<{ name: string; xff: string; count: number; want: string | null }> = [
		{
			name: "client-prepended entry is skipped",
			xff: "10.0.0.1, 203.0.113.9",
			count: 1,
			want: "203.0.113.9",
		},
		{
			name: "two proxies, spoof at the front",
			xff: "10.0.0.1, 198.51.100.2, 203.0.113.9",
			count: 2,
			want: "198.51.100.2",
		},
		{
			name: "count above chain length clamps to the first",
			xff: "203.0.113.9",
			count: 5,
			want: "203.0.113.9",
		},
		{ name: "empty segments are dropped", xff: ", ,203.0.113.9,", count: 1, want: "203.0.113.9" },
		{ name: "injection characters are rejected", xff: "203.0.113.9; DROP", count: 1, want: null },
		{ name: "oversized value is rejected", xff: "a".repeat(65), count: 1, want: null },
		{ name: "blank header", xff: " ", count: 1, want: null },
	];
	for (const c of cases) {
		it(c.name, () => {
			expect(
				resolveClientIp(req({ "x-forwarded-for": c.xff }), { trustedProxyCount: c.count }),
			).toBe(c.want);
		});
	}

	it("a trusted header wins over a forged X-Forwarded-For", () => {
		const r = req({ "x-forwarded-for": "10.0.0.1", "cf-connecting-ip": "203.0.113.9" });
		expect(resolveClientIp(r, { trustedHeader: "cf-connecting-ip", trustedProxyCount: 1 })).toBe(
			"203.0.113.9",
		);
	});

	it("a missing trusted header yields null, not a fallback to X-Forwarded-For", () => {
		const r = req({ "x-forwarded-for": "10.0.0.1" });
		expect(resolveClientIp(r, { trustedHeader: "cf-connecting-ip" })).toBeNull();
	});
});
