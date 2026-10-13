import { describe, expect, it } from "vitest";
import { createAdapterAdmission } from "../src/adapter-admit.js";
import { memoryStorage } from "../src/storage/memory.js";
import type { SecondaryStorage } from "../src/storage/types.js";

const proxy = { trustedHeader: "x-real-ip" };

function req(method: string, path: string, headers: Record<string, string> = {}): Request {
	return new Request(`https://api.example.com/auth${path}`, { method, headers });
}

describe("adapter admission: rate limiting", () => {
	it("refuses a strict route after its limit, with Retry-After", async () => {
		const a = createAdapterAdmission({ rateLimit: { strict: { max: 2, window: 60 } } }, proxy);
		const r = () => req("POST", "/mcp/token", { "x-real-ip": "1.1.1.1" });
		expect(await a.admit(r(), "/mcp/token")).toBeNull();
		expect(await a.admit(r(), "/mcp/token")).toBeNull();
		const denied = await a.admit(r(), "/mcp/token");
		expect(denied?.status).toBe(429);
		expect(Number(denied?.headers.get("retry-after"))).toBeGreaterThanOrEqual(1);
	});

	it("keeps tiers and clients separate", async () => {
		const a = createAdapterAdmission({ rateLimit: { strict: { max: 1, window: 60 } } }, proxy);
		expect(
			await a.admit(req("POST", "/mcp/token", { "x-real-ip": "1.1.1.1" }), "/mcp/token"),
		).toBeNull();
		expect(
			await a.admit(req("POST", "/mcp/token", { "x-real-ip": "1.1.1.1" }), "/mcp/token"),
		).not.toBeNull();
		expect(
			await a.admit(req("POST", "/mcp/token", { "x-real-ip": "2.2.2.2" }), "/mcp/token"),
		).toBeNull();
		expect(await a.admit(req("GET", "/agents", { "x-real-ip": "1.1.1.1" }), "/agents")).toBeNull();
	});

	it("splits callers by credential when the client IP is unknown", async () => {
		const a = createAdapterAdmission({ rateLimit: { read: { max: 1, window: 60 } } }, undefined);
		const as = (token: string) => req("GET", "/agents", { authorization: `Bearer ${token}` });
		expect(await a.admit(as("a"), "/agents")).toBeNull();
		expect(await a.admit(as("a"), "/agents")).not.toBeNull();
		expect(await a.admit(as("b"), "/agents")).toBeNull();
	});

	it("can be turned off", async () => {
		const a = createAdapterAdmission({ rateLimit: false }, proxy);
		for (let i = 0; i < 500; i++) {
			expect(await a.admit(req("POST", "/mcp/token"), "/mcp/token")).toBeNull();
		}
	});
});

describe("adapter admission: cross-site writes", () => {
	const a = createAdapterAdmission(
		{ rateLimit: false, trustedOrigins: ["https://app.example.com"] },
		proxy,
	);
	const cookie = { cookie: "theauth_session=abc" };

	it("refuses a cookie write from another origin", async () => {
		const r = req("POST", "/agents", { ...cookie, origin: "https://evil.example" });
		expect((await a.admit(r, "/agents"))?.status).toBe(403);
	});

	it("refuses an opaque origin and cross-site fetch metadata", async () => {
		expect(
			(await a.admit(req("POST", "/agents", { ...cookie, origin: "null" }), "/agents"))?.status,
		).toBe(403);
		const meta = req("POST", "/agents", { ...cookie, "sec-fetch-site": "cross-site" });
		expect((await a.admit(meta, "/agents"))?.status).toBe(403);
	});

	it("allows own origin, trusted origins, safe methods and bearer callers", async () => {
		const own = req("POST", "/agents", { ...cookie, origin: "https://api.example.com" });
		expect(await a.admit(own, "/agents")).toBeNull();
		const trusted = req("POST", "/agents", { ...cookie, origin: "https://app.example.com" });
		expect(await a.admit(trusted, "/agents")).toBeNull();
		const safe = req("GET", "/agents", { ...cookie, origin: "https://evil.example" });
		expect(await a.admit(safe, "/agents")).toBeNull();
		const bearer = req("POST", "/agents", {
			...cookie,
			authorization: "Bearer t",
			origin: "https://evil.example",
		});
		expect(await a.admit(bearer, "/agents")).toBeNull();
	});

	it("can be turned off", async () => {
		const off = createAdapterAdmission({ rateLimit: false, csrf: false }, proxy);
		const r = req("POST", "/agents", { ...cookie, origin: "https://evil.example" });
		expect(await off.admit(r, "/agents")).toBeNull();
	});
});

describe("adapter admission: shared counter store", () => {
	const limits = { rateLimit: { strict: { max: 2, window: 60 } } };
	const r = () => req("POST", "/mcp/token", { "x-real-ip": "1.1.1.1" });

	it("enforces one limit across instances that share a store", async () => {
		const store = memoryStorage();
		const one = createAdapterAdmission(limits, proxy, store);
		const two = createAdapterAdmission(limits, proxy, store);
		expect(await one.admit(r(), "/mcp/token")).toBeNull();
		expect(await two.admit(r(), "/mcp/token")).toBeNull();
		const denied = await one.admit(r(), "/mcp/token");
		expect(denied?.status).toBe(429);
		expect(Number(denied?.headers.get("retry-after"))).toBeGreaterThanOrEqual(1);
		expect((await two.admit(r(), "/mcp/token"))?.status).toBe(429);
	});

	it("lets requests through when the store fails", async () => {
		const broken: SecondaryStorage = {
			...memoryStorage(),
			incr: async () => {
				throw new Error("store down");
			},
		};
		const a = createAdapterAdmission(limits, proxy, broken);
		for (let i = 0; i < 5; i++) expect(await a.admit(r(), "/mcp/token")).toBeNull();
	});
});
