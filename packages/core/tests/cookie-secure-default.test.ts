/** Secure default, prefix validation and runtime independence for the shared cookie serializer. */

import { afterEach, describe, expect, it, vi } from "vitest";
import { buildClearCookie, buildSetCookie } from "../src/plugin/helpers.js";
import { resolveCookieSecure, serializeCookie } from "../src/session/cookie.js";

const req = (url: string, headers: Record<string, string> = {}) => new Request(url, { headers });
const hasSecure = (h: string) => h.split("; ").includes("Secure");

describe("Secure default", () => {
	afterEach(() => vi.unstubAllEnvs());

	it("is Secure with no request and no options", () => {
		expect(hasSecure(serializeCookie("s", "v"))).toBe(true);
	});

	it("gives the same result for NODE_ENV unset, production and development", () => {
		const results: boolean[] = [];
		for (const env of [undefined, "production", "development", "test"]) {
			if (env === undefined) vi.stubEnv("NODE_ENV", "");
			else vi.stubEnv("NODE_ENV", env);
			results.push(
				hasSecure(serializeCookie("s", "v")),
				hasSecure(serializeCookie("s", "v", { request: req("http://localhost:3000/") })),
				hasSecure(serializeCookie("s", "v", { request: req("https://app.example.com/") })),
			);
		}
		expect(new Set(results.filter((_, i) => i % 3 === 0))).toEqual(new Set([true]));
		expect(results.filter((_, i) => i % 3 === 1)).toEqual([false, false, false, false]);
		expect(results.filter((_, i) => i % 3 === 2)).toEqual([true, true, true, true]);
	});

	it("is Secure on https and on plain http for non-loopback hosts", () => {
		expect(resolveCookieSecure(req("https://example.com/"))).toBe(true);
		expect(resolveCookieSecure(req("http://example.com/"))).toBe(true);
	});

	it("is not Secure only for http on localhost or loopback", () => {
		expect(resolveCookieSecure(req("http://localhost:3000/"))).toBe(false);
		expect(resolveCookieSecure(req("http://127.0.0.1:8787/"))).toBe(false);
		expect(resolveCookieSecure(req("http://[::1]:3000/"))).toBe(false);
		expect(resolveCookieSecure(req("http://app.localhost/"))).toBe(false);
		expect(resolveCookieSecure(req("https://localhost/"))).toBe(true);
	});

	it("honors an explicit secure option over the request", () => {
		expect(resolveCookieSecure(req("https://example.com/"), { secure: false })).toBe(false);
		expect(resolveCookieSecure(req("http://localhost/"), { secure: true })).toBe(true);
		expect(hasSecure(serializeCookie("s", "v", { secure: false }))).toBe(false);
	});

	it("uses x-forwarded-proto only when the proxy is trusted", () => {
		const r = req("http://internal:3000/", { "x-forwarded-proto": "https" });
		expect(resolveCookieSecure(r, { trustProxy: true })).toBe(true);
		expect(resolveCookieSecure(r, { trustProxy: { trustedProxyCount: 1 } })).toBe(true);
		const local = req("http://localhost:3000/", { "x-forwarded-proto": "https" });
		expect(resolveCookieSecure(local)).toBe(false);
		expect(resolveCookieSecure(local, { trustProxy: true })).toBe(true);
		const spoof = req("http://localhost:3000/", { "x-forwarded-proto": "https" });
		expect(resolveCookieSecure(spoof, { trustProxy: { trustedProxyCount: 0 } })).toBe(false);
	});

	it("plugin cookie helpers go through the shared serializer", () => {
		expect(hasSecure(buildSetCookie("a", "b", 60))).toBe(true);
		expect(hasSecure(buildSetCookie("a", "b", 60, "/", false))).toBe(false);
		expect(buildClearCookie("a")).toContain("Max-Age=0");
		expect(hasSecure(buildClearCookie("a"))).toBe(true);
	});
});

describe("attributes", () => {
	it("emits Domain, Max-Age and Partitioned", () => {
		const h = serializeCookie("s", "v", {
			domain: "example.com",
			maxAge: 60,
			partitioned: true,
			sameSite: "none",
		});
		expect(h).toContain("Domain=example.com");
		expect(h).toContain("Max-Age=60");
		expect(h).toContain("SameSite=None");
		expect(h.endsWith("Partitioned")).toBe(true);
	});
});

describe("prefix validation", () => {
	it("accepts a valid __Host- cookie", () => {
		const h = serializeCookie("__Host-sid", "v");
		expect(h).toContain("Secure");
		expect(h).toContain("Path=/");
	});

	it("rejects invalid __Host- combinations", () => {
		expect(() => serializeCookie("__Host-sid", "v", { secure: false })).toThrow(/__Host-/);
		expect(() => serializeCookie("__Host-sid", "v", { path: "/app" })).toThrow(/Path=\//);
		expect(() => serializeCookie("__Host-sid", "v", { domain: "example.com" })).toThrow(/Domain/);
		expect(() => serializeCookie("__Host-sid", "v", { request: req("http://localhost/") })).toThrow(
			/Secure/,
		);
	});

	it("requires Secure for __Secure-, Partitioned and SameSite=None", () => {
		expect(hasSecure(serializeCookie("__Secure-sid", "v", { domain: "example.com" }))).toBe(true);
		expect(() => serializeCookie("__Secure-sid", "v", { secure: false })).toThrow(/__Secure-/);
		expect(() => serializeCookie("a", "v", { secure: false, partitioned: true })).toThrow(
			/Partitioned/,
		);
		expect(() => serializeCookie("a", "v", { secure: false, sameSite: "none" })).toThrow(
			/SameSite=None/,
		);
	});
});
