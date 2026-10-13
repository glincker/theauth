import express from "express";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { createTheAuth } from "../../../core/src/theauth.js";
import { buildTheAuthRouter } from "../src/adapter.js";

/**
 * The token endpoint must forward the AS DPoP nonce (RFC 9449 section 8) so
 * clients can complete the `use_dpop_nonce` retry, and expose it to browsers.
 */

const NONCE = "nonce-from-as";

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

describe("NestJS DPoP-Nonce forwarding", () => {
	it("forwards DPoP-Nonce on a use_dpop_nonce token error", async () => {
		const app = express();
		app.use(express.json());
		app.use(
			"/api/auth/theauth",
			buildTheAuthRouter(await makeTheAuth(), stubMcp, { allowUnauthenticated: true }),
		);
		const res = await request(app)
			.post("/api/auth/theauth/mcp/token")
			.set("DPoP", "proof")
			.send({ grant_type: "authorization_code" });
		expect(res.status).toBe(400);
		expect(res.headers["dpop-nonce"]).toBe(NONCE);
		expect(res.headers["access-control-expose-headers"]).toContain("DPoP-Nonce");
		expect(res.body.error).toBe("use_dpop_nonce");
	});
});
