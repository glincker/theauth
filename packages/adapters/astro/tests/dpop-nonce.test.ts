import { describe, expect, it } from "vitest";
import { createTheAuth } from "../../../core/src/theauth.js";
import { theAuthAstro } from "../src/adapter.js";

/**
 * The token endpoint must forward the AS DPoP nonce (RFC 9449 section 8) so
 * clients can complete the `use_dpop_nonce` retry, and expose it to browsers.
 */
const NONCE = "nonce-from-as";
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

function tokenRequest(): Request {
	return new Request(`${BASE_URL}/mcp/token`, {
		method: "POST",
		headers: { "Content-Type": "application/x-www-form-urlencoded", DPoP: "proof" },
		body: "grant_type=authorization_code",
	});
}

async function makeTheAuth() {
	return createTheAuth({ database: { provider: "sqlite", url: ":memory:" } });
}

describe("Astro DPoP-Nonce forwarding", () => {
	it("forwards DPoP-Nonce on a use_dpop_nonce token error and exposes it to browsers", async () => {
		const handlers = theAuthAstro(await makeTheAuth(), {
			basePath: "/api/auth/theauth",
			allowUnauthenticated: true,
			mcp: stubMcp,
		});
		const res = await handlers.POST({ request: tokenRequest() } as never);
		expect(res.status).toBe(400);
		expect(res.headers.get("dpop-nonce")).toBe(NONCE);
		expect(res.headers.get("access-control-expose-headers")).toContain("DPoP-Nonce");
		expect(res.headers.get("access-control-allow-headers")).toContain("DPoP");
		expect(((await res.json()) as { error: string }).error).toBe("use_dpop_nonce");
	});
});
