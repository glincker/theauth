import { describe, expect, it } from "vitest";
import { createTheAuth } from "../../../core/src/theauth.js";
import { theAuthHono } from "../src/adapter.js";

/**
 * The token endpoint must forward the AS DPoP nonce (RFC 9449 section 8) so
 * clients can complete the `use_dpop_nonce` retry, and expose it to browsers.
 */

const NONCE = "nonce-from-as";
const FORM = "grant_type=authorization_code";

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
	it("forwards DPoP-Nonce on a use_dpop_nonce token error", async () => {
		const app = theAuthHono(await makeTheAuth(), { allowUnauthenticated: true, mcp: stubMcp });
		const res = await app.request("/mcp/token", {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded", DPoP: "proof" },
			body: FORM,
		});
		expect(res.status).toBe(400);
		expect(res.headers.get("dpop-nonce")).toBe(NONCE);
		expect(res.headers.get("access-control-expose-headers")).toContain("DPoP-Nonce");
	});
});
