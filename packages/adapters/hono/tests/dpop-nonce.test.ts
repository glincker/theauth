import { describe, expect, it } from "vitest";
import { createTheAuth } from "../../../core/src/theauth.js";
import { theAuthHono } from "../src/adapter.js";

/**
 * The token endpoint must forward the AS DPoP nonce (RFC 9449 section 8) so
 * clients can complete the `use_dpop_nonce` retry, and, only when CORS is opted in, expose it to browsers.
 */

const NONCE = "nonce-from-as";
const ORIGIN = "https://app.example.com";
const CORS = { origins: [ORIGIN], groups: { token: true } };
const FORM = "grant_type=authorization_code";

type HonoOptions = NonNullable<Parameters<typeof theAuthHono>[1]>;

function post(app: ReturnType<typeof theAuthHono>, origin?: string): Response | Promise<Response> {
	return app.request("/mcp/token", {
		method: "POST",
		headers: {
			"Content-Type": "application/x-www-form-urlencoded",
			DPoP: "proof",
			...(origin ? { Origin: origin } : {}),
		},
		body: FORM,
	});
}

async function makeApp(extra: Partial<HonoOptions> = {}) {
	return theAuthHono(await makeTheAuth(), { allowUnauthenticated: true, mcp: stubMcp, ...extra });
}

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

async function makeTheAuth() {
	return createTheAuth({ database: { provider: "sqlite", url: ":memory:" } });
}

describe("Hono DPoP-Nonce forwarding", () => {
	it("forwards DPoP-Nonce on a use_dpop_nonce token error by default", async () => {
		const res = await post(await makeApp());
		expect(res.status).toBe(400);
		expect(res.headers.get("dpop-nonce")).toBe(NONCE);
		expect(res.headers.get("access-control-allow-origin")).toBeNull();
		expect(res.headers.get("access-control-expose-headers")).toBeNull();
	});

	it("without cors configured, sends no Access-Control-Allow-Origin even for a cross-origin caller", async () => {
		const res = await post(await makeApp(), ORIGIN);
		expect(res.headers.get("dpop-nonce")).toBe(NONCE);
		expect(res.headers.get("access-control-allow-origin")).toBeNull();
	});

	it("with cors enabled for the token group, exposes DPoP-Nonce to the exact origin only", async () => {
		const app = await makeApp({ cors: CORS });
		const res = await post(app, ORIGIN);
		expect(res.status).toBe(400);
		expect(res.headers.get("dpop-nonce")).toBe(NONCE);
		expect(res.headers.get("access-control-allow-origin")).toBe(ORIGIN);
		expect(res.headers.get("access-control-expose-headers")).toContain("DPoP-Nonce");
		const other = await post(app, "https://evil.example.com");
		expect(other.headers.get("access-control-allow-origin")).toBeNull();
	});
});
