import express from "express";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { createTheAuth } from "../../../core/src/theauth.js";
import { buildTheAuthRouter } from "../src/adapter.js";

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

type Extra = Partial<NonNullable<Parameters<typeof buildTheAuthRouter>[2]>>;

async function makeApp(extra: Extra = {}) {
	const app = express();
	app.use(express.json());
	app.use(
		"/api/auth/theauth",
		buildTheAuthRouter(await makeTheAuth(), stubMcp, { allowUnauthenticated: true, ...extra }),
	);
	return app;
}

function post(app: express.Express, origin?: string) {
	const req = request(app).post("/api/auth/theauth/mcp/token").set("DPoP", "proof");
	return (origin ? req.set("Origin", origin) : req).send({ grant_type: "authorization_code" });
}

describe("NestJS DPoP-Nonce forwarding", () => {
	it("forwards DPoP-Nonce on a use_dpop_nonce token error by default", async () => {
		const res = await post(await makeApp());
		expect(res.status).toBe(400);
		expect(res.headers["dpop-nonce"]).toBe(NONCE);
		expect(res.headers["access-control-allow-origin"]).toBeUndefined();
		expect(res.headers["access-control-expose-headers"]).toBeUndefined();
	});

	it("without cors configured, sends no Access-Control-Allow-Origin even for a cross-origin caller", async () => {
		const res = await post(await makeApp(), ORIGIN);
		expect(res.headers["dpop-nonce"]).toBe(NONCE);
		expect(res.headers["access-control-allow-origin"]).toBeUndefined();
	});

	it("with cors enabled for the token group, exposes DPoP-Nonce to the exact origin only", async () => {
		const app = await makeApp({ cors: CORS });
		const res = await post(app, ORIGIN);
		expect(res.status).toBe(400);
		expect(res.headers["dpop-nonce"]).toBe(NONCE);
		expect(res.headers["access-control-allow-origin"]).toBe(ORIGIN);
		expect(res.headers["access-control-expose-headers"]).toContain("DPoP-Nonce");
		const other = await post(app, "https://evil.example.com");
		expect(other.headers["access-control-allow-origin"]).toBeUndefined();
	});
});
