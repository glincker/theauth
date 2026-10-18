import { describe, expect, it } from "vitest";
import { createTheAuthHandler } from "../../src/http/index.js";
import { makeHarness } from "../mcp-test-harness.js";
import { BASE, makeAuth } from "./helpers.js";

type HandlerOptions = NonNullable<Parameters<typeof createTheAuthHandler>[1]>;

const APP = "https://app.example.com";
const EVIL = "https://evil.example.com";

async function setup(options: HandlerOptions = {}) {
	const auth = await makeAuth();
	const handler = createTheAuthHandler(auth, {
		mcp: makeHarness().mcp,
		rateLimit: false,
		allowUnauthenticated: true,
		...options,
	});
	return handler;
}

const get = (path: string, origin?: string) =>
	new Request(`${BASE}${path}`, { headers: origin ? { Origin: origin } : {} });
const preflight = (path: string, method: string, origin: string) =>
	new Request(`${BASE}${path}`, {
		method: "OPTIONS",
		headers: {
			Origin: origin,
			"Access-Control-Request-Method": method,
			"Access-Control-Request-Headers": "authorization",
		},
	});

describe("CORS off by default", () => {
	it("sends no CORS headers, not even on discovery or preflight", async () => {
		const handler = await setup();
		const doc = await handler(get("/.well-known/oauth-authorization-server", APP));
		expect(doc.status).toBe(200);
		expect(doc.headers.get("access-control-allow-origin")).toBeNull();
		const pre = await handler(preflight("/.well-known/oauth-authorization-server", "GET", APP));
		expect(pre.status).toBe(204);
		expect(pre.headers.get("access-control-allow-origin")).toBeNull();
	});
});

describe("CORS allowlist", () => {
	it("allows a listed origin on discovery documents with Vary: Origin", async () => {
		const handler = await setup({ cors: { origins: [APP] } });
		for (const path of [
			"/.well-known/oauth-authorization-server",
			"/.well-known/oauth-protected-resource",
			"/mcp/jwks",
		]) {
			const res = await handler(get(path, APP));
			expect(res.headers.get("access-control-allow-origin"), path).toBe(APP);
			expect(res.headers.get("vary"), path).toContain("Origin");
			expect(res.headers.get("access-control-expose-headers")).toContain("DPoP-Nonce");
		}
	});

	it("never reflects an unlisted origin, and still varies", async () => {
		const handler = await setup({ cors: { origins: [APP] } });
		const res = await handler(get("/.well-known/oauth-authorization-server", EVIL));
		expect(res.headers.get("access-control-allow-origin")).toBeNull();
		expect(res.headers.get("vary")).toContain("Origin");
		const none = await handler(get("/.well-known/oauth-authorization-server"));
		expect(none.headers.get("access-control-allow-origin")).toBeNull();
		const tricky = await handler(get("/.well-known/oauth-authorization-server", `${APP}.evil.com`));
		expect(tricky.headers.get("access-control-allow-origin")).toBeNull();
	});

	it("answers a preflight with methods, headers and max age", async () => {
		const handler = await setup({ cors: { origins: [APP], maxAge: 123 } });
		const res = await handler(preflight("/.well-known/oauth-authorization-server", "GET", APP));
		expect(res.status).toBe(204);
		expect(res.headers.get("access-control-allow-origin")).toBe(APP);
		expect(res.headers.get("access-control-allow-methods")).toBe("GET, OPTIONS");
		expect(res.headers.get("access-control-allow-headers")).toContain("Authorization");
		expect(res.headers.get("access-control-max-age")).toBe("123");
		expect(res.headers.get("vary")).toContain("Origin");
	});

	it("refuses a preflight from an unlisted origin or for a method the path lacks", async () => {
		const handler = await setup({ cors: { origins: [APP] } });
		const evil = await handler(preflight("/.well-known/oauth-authorization-server", "GET", EVIL));
		expect(evil.status).toBe(204);
		expect(evil.headers.get("access-control-allow-origin")).toBeNull();
		const method = await handler(
			preflight("/.well-known/oauth-authorization-server", "DELETE", APP),
		);
		expect(method.headers.get("access-control-allow-origin")).toBeNull();
	});

	it("uses the wildcard for public documents only when asked, without Vary or credentials", async () => {
		const handler = await setup({ cors: { origins: ["*"] } });
		const res = await handler(get("/mcp/jwks", EVIL));
		expect(res.headers.get("access-control-allow-origin")).toBe("*");
		expect(res.headers.get("access-control-allow-credentials")).toBeNull();
	});

	it("refuses a wildcard with credentials and a wildcard on credential groups", async () => {
		await expect(setup({ cors: { origins: ["*"], credentials: true } })).rejects.toThrow(
			/credentials/,
		);
		await expect(setup({ cors: { origins: ["*"], groups: { token: true } } })).rejects.toThrow(
			/token/,
		);
		await expect(setup({ cors: { origins: ["https://x.com/path"] } })).rejects.toThrow(
			/exact origin/,
		);
	});
});

describe("token, introspection and revoke are never CORS enabled implicitly", () => {
	it("stay closed when origins are listed", async () => {
		const handler = await setup({ cors: { origins: [APP] } });
		for (const path of [
			"/mcp/token",
			"/mcp/introspect",
			"/mcp/revoke",
			"/mcp/register",
			"/agents",
		]) {
			const method = path === "/agents" ? "GET" : "POST";
			const pre = await handler(preflight(path, method, APP));
			expect(pre.headers.get("access-control-allow-origin"), path).toBeNull();
			const res = await handler(
				new Request(`${BASE}${path}`, {
					method,
					headers: { Origin: APP, "Content-Type": "application/x-www-form-urlencoded" },
					body: method === "POST" ? "" : undefined,
				}),
			);
			expect(res.headers.get("access-control-allow-origin"), path).toBeNull();
		}
	});

	it("open per group once listed, with their own allowlist", async () => {
		const handler = await setup({
			cors: { origins: [APP], groups: { token: ["https://spa.example.com"], register: true } },
		});
		const spa = "https://spa.example.com";
		const ok = await handler(preflight("/mcp/token", "POST", spa));
		expect(ok.headers.get("access-control-allow-origin")).toBe(spa);
		const no = await handler(preflight("/mcp/token", "POST", APP));
		expect(no.headers.get("access-control-allow-origin")).toBeNull();
		const reg = await handler(preflight("/mcp/register", "POST", APP));
		expect(reg.headers.get("access-control-allow-origin")).toBe(APP);
		const revoke = await handler(preflight("/mcp/revoke", "POST", APP));
		expect(revoke.headers.get("access-control-allow-origin")).toBeNull();
	});

	it("sends credentials only with exact origins", async () => {
		const handler = await setup({
			cors: { origins: [APP], credentials: true, groups: { management: true } },
		});
		const res = await handler(get("/audit", APP));
		expect(res.headers.get("access-control-allow-origin")).toBe(APP);
		expect(res.headers.get("access-control-allow-credentials")).toBe("true");
	});
});
