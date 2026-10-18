import { createApp, toWebHandler, use } from "h3";
import { describe, expect, it } from "vitest";
import { createTheAuth } from "../../../core/src/theauth.js";
import { theAuthNuxt } from "../src/adapter.js";

/**
 * The token endpoint must forward the AS DPoP nonce (RFC 9449 section 8) so
 * clients can complete the `use_dpop_nonce` retry, and, only when CORS is opted in, expose it to browsers.
 */

const NONCE = "nonce-from-as";
const ORIGIN = "https://app.example.com";
const CORS = { origins: [ORIGIN], groups: { token: true } };
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

type NuxtOptions = NonNullable<Parameters<typeof theAuthNuxt>[1]>;

async function post(extra: Partial<NuxtOptions>, origin?: string): Promise<Response> {
	const app = createApp();
	use(
		app,
		theAuthNuxt(await makeTheAuth(), {
			basePath: "/api/auth/theauth",
			allowUnauthenticated: true,
			mcp: stubMcp,
			...extra,
		}),
	);
	return toWebHandler(app)(
		new Request("http://localhost/api/auth/theauth/mcp/token", {
			method: "POST",
			headers: {
				"Content-Type": "application/x-www-form-urlencoded",
				DPoP: "proof",
				...(origin ? { Origin: origin } : {}),
			},
			body: FORM,
		}),
	);
}

describe("Nuxt DPoP-Nonce forwarding", () => {
	it("forwards DPoP-Nonce on a use_dpop_nonce token error by default", async () => {
		const res = await post({});
		expect(res.status).toBe(400);
		expect(res.headers.get("dpop-nonce")).toBe(NONCE);
		expect(res.headers.get("access-control-allow-origin")).toBeNull();
		expect(res.headers.get("access-control-expose-headers")).toBeNull();
		expect(((await res.json()) as { error: string }).error).toBe("use_dpop_nonce");
	});

	it("without cors configured, sends no Access-Control-Allow-Origin even for a cross-origin caller", async () => {
		const res = await post({}, ORIGIN);
		expect(res.headers.get("dpop-nonce")).toBe(NONCE);
		expect(res.headers.get("access-control-allow-origin")).toBeNull();
	});

	it("with cors enabled for the token group, exposes DPoP-Nonce to the exact origin only", async () => {
		const res = await post({ cors: CORS }, ORIGIN);
		expect(res.status).toBe(400);
		expect(res.headers.get("dpop-nonce")).toBe(NONCE);
		expect(res.headers.get("access-control-allow-origin")).toBe(ORIGIN);
		expect(res.headers.get("access-control-expose-headers")).toContain("DPoP-Nonce");
		const other = await post({ cors: CORS }, "https://evil.example.com");
		expect(other.headers.get("access-control-allow-origin")).toBeNull();
	});
});
