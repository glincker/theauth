import { describe, expect, it } from "vitest";
import { createTheAuth } from "../../../core/src/theauth.js";
import { theAuthSvelteKit } from "../src/adapter.js";

/**
 * The token endpoint must forward the AS DPoP nonce (RFC 9449 section 8) so
 * clients can complete the `use_dpop_nonce` retry, and, only when CORS is opted in, expose it to browsers.
 */
const NONCE = "nonce-from-as";
const ORIGIN = "https://app.example.com";
const CORS = { origins: [ORIGIN], groups: { token: true } };
const BASE_URL = "http://localhost/api/auth/theauth";

const stubMcp = {
	token: async () => ({
		success: false as const,
		error: {
			code: "USE_DPOP_NONCE",
			message: "A server-provided DPoP nonce is required",
			details: { dpopNonce: NONCE },
		},
	}),
} as never;

function tokenRequest(origin?: string): Request {
	return new Request(`${BASE_URL}/mcp/token`, {
		method: "POST",
		headers: {
			"Content-Type": "application/x-www-form-urlencoded",
			DPoP: "proof",
			...(origin ? { Origin: origin } : {}),
		},
		body: "grant_type=authorization_code",
	});
}

async function makeTheAuth() {
	return createTheAuth({ database: { provider: "sqlite", url: ":memory:" } });
}

describe("SvelteKit DPoP-Nonce forwarding", () => {
	it("forwards DPoP-Nonce on a use_dpop_nonce token error by default", async () => {
		const handlers = theAuthSvelteKit(await makeTheAuth(), {
			basePath: "/api/auth/theauth",
			allowUnauthenticated: true,
			mcp: stubMcp,
		});
		const res = await handlers.POST({ request: tokenRequest() } as never);
		expect(res.status).toBe(400);
		expect(res.headers.get("dpop-nonce")).toBe(NONCE);
		expect(res.headers.get("access-control-allow-origin")).toBeNull();
		expect(res.headers.get("access-control-expose-headers")).toBeNull();
		expect(((await res.json()) as { error: string }).error).toBe("use_dpop_nonce");
	});

	it("without cors configured, sends no Access-Control-Allow-Origin even for a cross-origin caller", async () => {
		const handlers = theAuthSvelteKit(await makeTheAuth(), {
			basePath: "/api/auth/theauth",
			allowUnauthenticated: true,
			mcp: stubMcp,
		});
		const res = await handlers.POST({ request: tokenRequest(ORIGIN) } as never);
		expect(res.headers.get("dpop-nonce")).toBe(NONCE);
		expect(res.headers.get("access-control-allow-origin")).toBeNull();
	});

	it("with cors enabled for the token group, exposes DPoP-Nonce to the exact origin only", async () => {
		const handlers = theAuthSvelteKit(await makeTheAuth(), {
			basePath: "/api/auth/theauth",
			allowUnauthenticated: true,
			mcp: stubMcp,
			cors: CORS,
		});
		const res = await handlers.POST({ request: tokenRequest(ORIGIN) } as never);
		expect(res.status).toBe(400);
		expect(res.headers.get("dpop-nonce")).toBe(NONCE);
		expect(res.headers.get("access-control-allow-origin")).toBe(ORIGIN);
		expect(res.headers.get("access-control-expose-headers")).toContain("DPoP-Nonce");
		const other = await handlers.POST({
			request: tokenRequest("https://evil.example.com"),
		} as never);
		expect(other.headers.get("access-control-allow-origin")).toBeNull();
	});
});
