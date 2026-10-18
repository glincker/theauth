import { describe, expect, it, vi } from "vitest";
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

	it("never lets a random Cookie or Authorization value mint a new bucket when the IP is unknown", async () => {
		const a = createAdapterAdmission({ rateLimit: { read: { max: 3, window: 60 } } }, undefined);
		let admitted = 0;
		for (let i = 0; i < 200; i++) {
			const r = req("GET", "/agents", { cookie: `x=${i}-${Math.random()}` });
			if ((await a.admit(r, "/agents")) === null) admitted++;
		}
		expect(admitted).toBe(3);
		let bearer = 0;
		for (let i = 0; i < 200; i++) {
			const r = req("GET", "/agents", { authorization: `Bearer t${i}` });
			if ((await a.admit(r, "/agents")) === null) bearer++;
		}
		expect(bearer).toBe(3);
	});

	it("keeps anonymous, cookie and authorization fallbacks in separate buckets", async () => {
		const a = createAdapterAdmission({ rateLimit: { read: { max: 1, window: 60 } } }, undefined);
		expect(await a.admit(req("GET", "/agents"), "/agents")).toBeNull();
		expect(await a.admit(req("GET", "/agents"), "/agents")).not.toBeNull();
		// A flood of anonymous traffic does not lock out callers that carry a credential.
		expect(await a.admit(req("GET", "/agents", { cookie: "s=1" }), "/agents")).toBeNull();
		expect(
			await a.admit(req("GET", "/agents", { authorization: "Bearer a" }), "/agents"),
		).toBeNull();
	});

	it("logs one warning on the first unknown-IP request, none with a trusted IP", async () => {
		const warn = vi.fn();
		const a = createAdapterAdmission({ logger: { warn } }, undefined);
		await a.admit(req("GET", "/agents"), "/agents");
		await a.admit(req("GET", "/agents"), "/agents");
		const unknown = warn.mock.calls.filter((c) => String(c[0]).includes("client IP"));
		expect(unknown).toHaveLength(1);

		const warn2 = vi.fn();
		const b = createAdapterAdmission({ logger: { warn: warn2 } }, proxy);
		await b.admit(req("GET", "/agents", { "x-real-ip": "1.1.1.1" }), "/agents");
		expect(warn2).not.toHaveBeenCalled();
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

describe("adapter admission: customization", () => {
	it("skips rate limiting for requests the host excludes", async () => {
		const a = createAdapterAdmission(
			{
				rateLimit: {
					read: { max: 1, window: 60 },
					skip: (_r, path) => path === "/health",
				},
			},
			proxy,
		);
		const r = () => req("GET", "/health", { "x-real-ip": "1.1.1.1" });
		for (let i = 0; i < 5; i++) expect(await a.admit(r(), "/health")).toBeNull();
		const other = () => req("GET", "/agents", { "x-real-ip": "1.1.1.1" });
		expect(await a.admit(other(), "/agents")).toBeNull();
		expect((await a.admit(other(), "/agents"))?.status).toBe(429);
	});

	it("counts by a host supplied key and falls back when it returns null", async () => {
		const a = createAdapterAdmission(
			{
				rateLimit: {
					read: { max: 1, window: 60 },
					key: (r) => r.headers.get("x-tenant"),
				},
			},
			proxy,
		);
		const as = (tenant: string, ip: string) =>
			req("GET", "/agents", { "x-tenant": tenant, "x-real-ip": ip });
		expect(await a.admit(as("acme", "1.1.1.1"), "/agents")).toBeNull();
		// Same tenant from another IP shares the bucket.
		expect((await a.admit(as("acme", "2.2.2.2"), "/agents"))?.status).toBe(429);
		expect(await a.admit(as("globex", "1.1.1.1"), "/agents")).toBeNull();
		const noTenant = () => req("GET", "/agents", { "x-real-ip": "3.3.3.3" });
		expect(await a.admit(noTenant(), "/agents")).toBeNull();
		expect((await a.admit(noTenant(), "/agents"))?.status).toBe(429);
	});
});
