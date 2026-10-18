import Fastify from "fastify";
import { describe, expect, it } from "vitest";
import { createTheAuth } from "../../../core/src/theauth.js";
import { theAuthFastify } from "../src/adapter.js";

/**
 * The token endpoint must forward the AS DPoP nonce (RFC 9449 section 8) so
 * clients can complete the `use_dpop_nonce` retry, and, only when CORS is opted in, expose it to browsers.
 */

const NONCE = "nonce-from-as";
const ORIGIN = "https://app.example.com";
const CORS = { origins: [ORIGIN], groups: { token: true } };

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

type FastifyOptions = NonNullable<Parameters<typeof theAuthFastify>[1]>;

async function makeApp(extra: Partial<FastifyOptions> = {}) {
	const app = Fastify();
	await app.register(
		theAuthFastify(await makeTheAuth(), { allowUnauthenticated: true, mcp: stubMcp, ...extra }),
		{ prefix: "/api/theauth" },
	);
	return app;
}

function post(app: Awaited<ReturnType<typeof makeApp>>, origin?: string) {
	return app.inject({
		method: "POST",
		url: "/api/theauth/mcp/token",
		headers: {
			"content-type": "application/json",
			dpop: "proof",
			...(origin ? { origin } : {}),
		},
		payload: { grant_type: "authorization_code" },
	});
}

describe("Fastify DPoP-Nonce forwarding", () => {
	it("forwards DPoP-Nonce on a use_dpop_nonce token error by default", async () => {
		const app = await makeApp();
		const res = await post(app);
		expect(res.statusCode).toBe(400);
		expect(res.headers["dpop-nonce"]).toBe(NONCE);
		expect(res.headers["access-control-allow-origin"]).toBeUndefined();
		expect(res.headers["access-control-expose-headers"]).toBeUndefined();
		expect(res.json().error).toBe("use_dpop_nonce");
		await app.close();
	});

	it("without cors configured, sends no Access-Control-Allow-Origin even for a cross-origin caller", async () => {
		const app = await makeApp();
		const res = await post(app, ORIGIN);
		expect(res.headers["dpop-nonce"]).toBe(NONCE);
		expect(res.headers["access-control-allow-origin"]).toBeUndefined();
		await app.close();
	});

	it("with cors enabled for the token group, exposes DPoP-Nonce to the exact origin only", async () => {
		const app = await makeApp({ cors: CORS });
		const res = await post(app, ORIGIN);
		expect(res.statusCode).toBe(400);
		expect(res.headers["dpop-nonce"]).toBe(NONCE);
		expect(res.headers["access-control-allow-origin"]).toBe(ORIGIN);
		expect(String(res.headers["access-control-expose-headers"])).toContain("DPoP-Nonce");
		const other = await post(app, "https://evil.example.com");
		expect(other.headers["access-control-allow-origin"]).toBeUndefined();
		await app.close();
	});
});
