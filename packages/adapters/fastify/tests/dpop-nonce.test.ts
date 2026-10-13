import Fastify from "fastify";
import { describe, expect, it } from "vitest";
import { createTheAuth } from "../../../core/src/theauth.js";
import { theAuthFastify } from "../src/adapter.js";

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

describe("Fastify DPoP-Nonce forwarding", () => {
	it("forwards DPoP-Nonce on a use_dpop_nonce token error", async () => {
		const app = Fastify();
		await app.register(
			theAuthFastify(await makeTheAuth(), { allowUnauthenticated: true, mcp: stubMcp }),
			{ prefix: "/api/theauth" },
		);
		const res = await app.inject({
			method: "POST",
			url: "/api/theauth/mcp/token",
			headers: { "content-type": "application/json", dpop: "proof" },
			payload: { grant_type: "authorization_code" },
		});
		expect(res.statusCode).toBe(400);
		expect(res.headers["dpop-nonce"]).toBe(NONCE);
		expect(String(res.headers["access-control-expose-headers"])).toContain("DPoP-Nonce");
		expect(res.json().error).toBe("use_dpop_nonce");
		await app.close();
	});
});
