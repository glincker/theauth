import { NextRequest } from "next/server";
import { describe, expect, it } from "vitest";
import { createAuthConfig } from "../src/config.js";
import { createSessionMarker } from "../src/session-marker.js";

const SECRET = "test-secret-test-secret-test-secret-0123456789";
const { withAuth } = await import("../src/middleware.js");

function jwt(expOffsetS: number): string {
	const b = (o: object) => btoa(JSON.stringify(o)).replace(/=+$/, "");
	return `${b({ alg: "none" })}.${b({ exp: Math.floor(Date.now() / 1000) + expOffsetS })}.sig`;
}

const config = createAuthConfig({
	backendUrl: "https://api.example.com",
	appUrl: "https://example.com",
	secret: SECRET,
	isProd: true,
});
const mw = withAuth(config, { protectedPaths: ["/app"] });

function req(cookie: string): NextRequest {
	return new NextRequest("https://example.com/app/x", { headers: { cookie } });
}

describe("middleware gate verifies a signed marker", () => {
	it("redirects when the token cookie is arbitrary (no marker)", async () => {
		const res = await mw(req(`__Host-glinr-token=${jwt(3600)}`));
		expect(res.status).toBe(307);
	});
	it("redirects when the marker is forged", async () => {
		const t = jwt(3600);
		const res = await mw(req(`__Host-glinr-token=${t}; ${config.cookies.markerName}=AAAA`));
		expect(res.status).toBe(307);
	});
	it("redirects when the marker belongs to a different token", async () => {
		const m = await createSessionMarker(SECRET, jwt(7200));
		const res = await mw(req(`__Host-glinr-token=${jwt(3600)}; ${config.cookies.markerName}=${m}`));
		expect(res.status).toBe(307);
	});
	it("redirects when the marker was signed with another secret", async () => {
		const t = jwt(3600);
		const m = await createSessionMarker("x".repeat(40), t);
		const res = await mw(req(`__Host-glinr-token=${t}; ${config.cookies.markerName}=${m}`));
		expect(res.status).toBe(307);
	});
	it("allows a token with its valid marker", async () => {
		const t = jwt(3600);
		const m = await createSessionMarker(SECRET, t);
		const res = await mw(req(`__Host-glinr-token=${t}; ${config.cookies.markerName}=${m}`));
		expect(res.status).toBe(200);
	});
	it("ignores a plain-name token when __Host- is in use", async () => {
		const t = jwt(3600);
		const m = await createSessionMarker(SECRET, t);
		const res = await mw(req(`glinr-token=${t}; glinr-gate=${m}`));
		expect(res.status).toBe(307);
	});
});
