import { describe, expect, it } from "vitest";
import { createAdapterAdmission } from "../src/adapter-admit.js";

const proxy = { trustedHeader: "x-real-ip" };

function req(method: string, path: string, headers: Record<string, string> = {}): Request {
	return new Request(`https://api.example.com/auth${path}`, { method, headers });
}

describe("adapter admission: rate limiting", () => {
	it("refuses a strict route after its limit, with Retry-After", async () => {
		const a = createAdapterAdmission({ rateLimit: { strict: { max: 2, window: 60 } } }, proxy);
		const r = () => req("POST", "/mcp/token", { "x-real-ip": "1.1.1.1" });
		expect(a.admit(r(), "/mcp/token")).toBeNull();
		expect(a.admit(r(), "/mcp/token")).toBeNull();
		const denied = a.admit(r(), "/mcp/token");
		expect(denied?.status).toBe(429);
		expect(Number(denied?.headers.get("retry-after"))).toBeGreaterThanOrEqual(1);
	});

	it("keeps tiers and clients separate", () => {
		const a = createAdapterAdmission({ rateLimit: { strict: { max: 1, window: 60 } } }, proxy);
		expect(a.admit(req("POST", "/mcp/token", { "x-real-ip": "1.1.1.1" }), "/mcp/token")).toBeNull();
		expect(
			a.admit(req("POST", "/mcp/token", { "x-real-ip": "1.1.1.1" }), "/mcp/token"),
		).not.toBeNull();
		expect(a.admit(req("POST", "/mcp/token", { "x-real-ip": "2.2.2.2" }), "/mcp/token")).toBeNull();
		expect(a.admit(req("GET", "/agents", { "x-real-ip": "1.1.1.1" }), "/agents")).toBeNull();
	});

	it("splits callers by credential when the client IP is unknown", () => {
		const a = createAdapterAdmission({ rateLimit: { read: { max: 1, window: 60 } } }, undefined);
		const as = (token: string) => req("GET", "/agents", { authorization: `Bearer ${token}` });
		expect(a.admit(as("a"), "/agents")).toBeNull();
		expect(a.admit(as("a"), "/agents")).not.toBeNull();
		expect(a.admit(as("b"), "/agents")).toBeNull();
	});

	it("can be turned off", () => {
		const a = createAdapterAdmission({ rateLimit: false }, proxy);
		for (let i = 0; i < 500; i++) {
			expect(a.admit(req("POST", "/mcp/token"), "/mcp/token")).toBeNull();
		}
	});
});

describe("adapter admission: cross-site writes", () => {
	const a = createAdapterAdmission(
		{ rateLimit: false, trustedOrigins: ["https://app.example.com"] },
		proxy,
	);
	const cookie = { cookie: "theauth_session=abc" };

	it("refuses a cookie write from another origin", () => {
		const r = req("POST", "/agents", { ...cookie, origin: "https://evil.example" });
		expect(a.admit(r, "/agents")?.status).toBe(403);
	});

	it("refuses an opaque origin and cross-site fetch metadata", () => {
		expect(a.admit(req("POST", "/agents", { ...cookie, origin: "null" }), "/agents")?.status).toBe(
			403,
		);
		const meta = req("POST", "/agents", { ...cookie, "sec-fetch-site": "cross-site" });
		expect(a.admit(meta, "/agents")?.status).toBe(403);
	});

	it("allows own origin, trusted origins, safe methods and bearer callers", () => {
		const own = req("POST", "/agents", { ...cookie, origin: "https://api.example.com" });
		expect(a.admit(own, "/agents")).toBeNull();
		const trusted = req("POST", "/agents", { ...cookie, origin: "https://app.example.com" });
		expect(a.admit(trusted, "/agents")).toBeNull();
		const safe = req("GET", "/agents", { ...cookie, origin: "https://evil.example" });
		expect(a.admit(safe, "/agents")).toBeNull();
		const bearer = req("POST", "/agents", {
			...cookie,
			authorization: "Bearer t",
			origin: "https://evil.example",
		});
		expect(a.admit(bearer, "/agents")).toBeNull();
	});

	it("can be turned off", () => {
		const off = createAdapterAdmission({ rateLimit: false, csrf: false }, proxy);
		const r = req("POST", "/agents", { ...cookie, origin: "https://evil.example" });
		expect(off.admit(r, "/agents")).toBeNull();
	});
});
