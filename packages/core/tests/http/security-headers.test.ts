import { describe, expect, it, vi } from "vitest";
import {
	createTheAuthHandler,
	isSecureRequest,
	listRoutes,
	securityHeaders,
} from "../../src/http/index.js";
import { makeHarness } from "../mcp-test-harness.js";
import { BASE, makeAuth } from "./helpers.js";

type HandlerOptions = NonNullable<Parameters<typeof createTheAuthHandler>[1]>;

async function setup(options: HandlerOptions = {}) {
	const auth = await makeAuth();
	const h = makeHarness();
	const handler = createTheAuthHandler(auth, {
		mcp: h.mcp,
		rateLimit: false,
		allowUnauthenticated: true,
		...options,
	});
	return { auth, handler };
}

function callOf(method: string, path: string, init: RequestInit = {}): Request {
	const concrete = path.replaceAll(/:[A-Za-z]+/g, "x");
	const hasBody = method !== "GET";
	return new Request(`${BASE}${concrete}`, {
		method,
		headers: hasBody ? { "Content-Type": "application/json" } : {},
		body: hasBody ? "{}" : undefined,
		...init,
	});
}

describe("default Cache-Control no-store", () => {
	it("every route in listRoutes() answers with no-store and Pragma", async () => {
		const { handler } = await setup();
		const routes = listRoutes({ mcp: makeHarness().mcp });
		expect(routes.length).toBeGreaterThan(10);
		for (const route of routes) {
			const res = await handler(callOf(route.method, route.path));
			const label = `${route.method} ${route.path} -> ${res.status}`;
			if (route.path === "/mcp/jwks") {
				// Public signing keys keep their own cacheable value.
				expect(res.headers.get("cache-control"), label).toMatch(/^public/);
				continue;
			}
			expect(res.headers.get("cache-control"), label).toBe("no-store");
			expect(res.headers.get("pragma"), label).toBe("no-cache");
		}
	});

	it("covers refusals and method errors but not an unknown route", async () => {
		const { handler } = await setup();
		const wrongMethod = await handler(callOf("DELETE", "/agents"));
		expect(wrongMethod.status).toBe(405);
		expect(wrongMethod.headers.get("cache-control")).toBe("no-store");
		const unknown = await handler(callOf("GET", "/nope"));
		expect(unknown.status).toBe(404);
		expect(unknown.headers.get("cache-control")).toBeNull();
	});

	it("covers authentication failures", async () => {
		const auth = await makeAuth();
		const handler = createTheAuthHandler(auth, { rateLimit: false });
		const res = await handler(callOf("GET", "/agents"));
		expect(res.status).toBe(401);
		expect(res.headers.get("cache-control")).toBe("no-store");
	});
});

describe("securityHeaders option", () => {
	const names = [
		"x-content-type-options",
		"referrer-policy",
		"cross-origin-resource-policy",
		"strict-transport-security",
		"x-frame-options",
		"content-security-policy",
	];

	it("sets nothing by default", async () => {
		const { handler } = await setup();
		const res = await handler(callOf("GET", "/audit"));
		for (const name of names) expect(res.headers.get(name), name).toBeNull();
	});

	it("sets the baseline headers on every served route when enabled", async () => {
		const { handler } = await setup({ securityHeaders: true });
		for (const route of listRoutes({ mcp: makeHarness().mcp })) {
			const res = await handler(callOf(route.method, route.path));
			expect(res.headers.get("x-content-type-options"), route.path).toBe("nosniff");
			expect(res.headers.get("referrer-policy"), route.path).toBe("no-referrer");
			expect(res.headers.get("cross-origin-resource-policy"), route.path).toBe("same-origin");
			// JSON routes are not HTML: no frame or CSP headers.
			expect(res.headers.get("x-frame-options"), route.path).toBeNull();
		}
	});

	it("sends HSTS only over https", async () => {
		const { handler } = await setup({ securityHeaders: true });
		const plain = await handler(callOf("GET", "/audit"));
		expect(plain.headers.get("strict-transport-security")).toBeNull();
		const secure = await handler(
			new Request(`https://localhost/api/theauth/audit`, { method: "GET" }),
		);
		expect(secure.headers.get("strict-transport-security")).toBe(
			"max-age=31536000; includeSubDomains",
		);
	});

	it("honors X-Forwarded-Proto only from a configured trusted proxy", async () => {
		const forwarded = { "x-forwarded-proto": "https" };
		const untrusted = await setup({ securityHeaders: true });
		const a = await untrusted.handler(callOf("GET", "/audit", { headers: forwarded }));
		expect(a.headers.get("strict-transport-security")).toBeNull();
		const trusted = await setup({ securityHeaders: true, trustedProxy: { trustedProxyCount: 1 } });
		const b = await trusted.handler(callOf("GET", "/audit", { headers: forwarded }));
		expect(b.headers.get("strict-transport-security")).not.toBeNull();
	});

	it("adds frame and CSP headers to HTML a plugin returns, and a handler value wins", async () => {
		const { auth, handler } = await setup({ securityHeaders: { referrerPolicy: "same-origin" } });
		vi.spyOn(auth.plugins, "handleRequest").mockResolvedValue(
			new Response("<p>hi</p>", {
				headers: { "Content-Type": "text/html", "Referrer-Policy": "origin" },
			}),
		);
		const res = await handler(callOf("GET", "/plugin-page"));
		expect(res.headers.get("x-frame-options")).toBe("DENY");
		expect(res.headers.get("content-security-policy")).toContain("frame-ancestors 'none'");
		expect(res.headers.get("referrer-policy")).toBe("origin");
	});

	it("leaves a 404 for an unknown route untouched", async () => {
		const { handler } = await setup({ securityHeaders: true });
		const res = await handler(new Request("https://localhost/elsewhere"));
		expect(res.status).toBe(404);
		for (const name of names) expect(res.headers.get(name), name).toBeNull();
		const inside = await handler(callOf("GET", "/nope"));
		expect(inside.status).toBe(404);
		expect(inside.headers.get("x-content-type-options")).toBeNull();
	});

	it("lets options turn headers off", async () => {
		const { handler } = await setup({
			securityHeaders: { referrerPolicy: false, crossOriginResourcePolicy: false, hsts: false },
		});
		const res = await handler(new Request("https://localhost/api/theauth/audit"));
		expect(res.headers.get("referrer-policy")).toBeNull();
		expect(res.headers.get("cross-origin-resource-policy")).toBeNull();
		expect(res.headers.get("strict-transport-security")).toBeNull();
		expect(res.headers.get("x-content-type-options")).toBe("nosniff");
	});
});

describe("securityHeaders() helper", () => {
	it("builds headers for your own responses", () => {
		expect(securityHeaders()).toEqual({
			"X-Content-Type-Options": "nosniff",
			"Referrer-Policy": "no-referrer",
			"Cross-Origin-Resource-Policy": "same-origin",
		});
		const html = securityHeaders({ secure: true, html: true });
		expect(html["Strict-Transport-Security"]).toContain("max-age=31536000");
		expect(html["X-Frame-Options"]).toBe("DENY");
		expect(html["Content-Security-Policy"]).toContain("default-src 'none'");
		expect(
			securityHeaders({ secure: true, hsts: { maxAge: 60, preload: true } })[
				"Strict-Transport-Security"
			],
		).toBe("max-age=60; includeSubDomains; preload");
	});

	it("isSecureRequest ignores forwarded headers without a trusted proxy", () => {
		const req = new Request("http://x/", { headers: { "x-forwarded-proto": "https" } });
		expect(isSecureRequest(req)).toBe(false);
		expect(isSecureRequest(req, { trustedHeader: "x-forwarded-proto" })).toBe(true);
		expect(isSecureRequest(new Request("https://x/"))).toBe(true);
	});
});

describe("startup warnings", () => {
	it("warns through the observability logger for allowUnauthenticated and permissive CORS", async () => {
		const { createTheAuth } = await import("../../src/theauth.js");
		const warn = vi.fn();
		const auth = await createTheAuth({
			database: { provider: "sqlite", url: ":memory:" },
			agents: {
				enabled: true,
				maxPerUser: 10,
				defaultPermissions: [],
				auditAll: true,
				tokenExpiry: "24h",
			},
			auth: { session: { secret: "test-session-secret-that-is-at-least-32-chars!!" } },
			logger: { debug: vi.fn(), info: vi.fn(), warn, error: vi.fn() },
		});
		vi.spyOn(console, "warn").mockImplementation(() => undefined);
		createTheAuthHandler(auth, {
			allowUnauthenticated: true,
			cors: { origins: ["*"] },
		});
		const text = warn.mock.calls.map((c) => String(c[0])).join("\n");
		expect(text).toContain("allowUnauthenticated");
		expect(text).toContain('allows any origin ("*")');
	});
});
