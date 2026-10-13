/**
 * `lenientClients`: opt-in compatibility for real-world MCP clients, plus the
 * step-up upgrade URL regression.
 */
import { describe, expect, it } from "vitest";
import type { McpConfig } from "../src/mcp/types.js";
import { computeS256Challenge, generateSecureToken } from "../src/mcp/utils.js";
import type { Harness } from "./mcp-test-harness.js";
import {
	addClient,
	BASE_URL,
	decodePayload,
	makeHarness,
	REDIRECT,
	RESOURCE,
	tokenRequest,
} from "./mcp-test-harness.js";

const LOOPBACK = "http://127.0.0.1:5000/cb";

async function authorize(h: Harness, clientId: string, params: Record<string, string | undefined>) {
	const verifier = generateSecureToken(43);
	const url = new URL(`${BASE_URL}/mcp/authorize`);
	const all: Record<string, string | undefined> = {
		response_type: "code",
		client_id: clientId,
		redirect_uri: REDIRECT,
		code_challenge: await computeS256Challenge(verifier),
		code_challenge_method: "S256",
		resource: RESOURCE,
		...params,
	};
	for (const [k, v] of Object.entries(all)) if (v !== undefined) url.searchParams.set(k, v);
	const res = await h.mcp.authorize(new Request(url));
	return { res, verifier };
}

async function fullFlow(
	h: Harness,
	clientId: string,
	authParams: Record<string, string | undefined>,
	tokenParams: Record<string, string | undefined> = {},
) {
	const { res, verifier } = await authorize(h, clientId, authParams);
	if (!res.success) return res;
	const code = new URL(res.data.redirectUri).searchParams.get("code") ?? "";
	const body: Record<string, string | undefined> = {
		grant_type: "authorization_code",
		code,
		redirect_uri: authParams.redirect_uri ?? REDIRECT,
		client_id: clientId,
		code_verifier: verifier,
		resource: "resource" in authParams ? authParams.resource : RESOURCE,
		...tokenParams,
	};
	const clean: Record<string, string> = {};
	for (const [k, v] of Object.entries(body)) if (v !== undefined) clean[k] = v;
	return h.mcp.token(tokenRequest(clean));
}

function harness(lenient?: McpConfig["lenientClients"], extra: Partial<McpConfig> = {}) {
	return makeHarness({ ...(lenient ? { lenientClients: lenient } : {}), ...extra });
}

describe("lenientClients defaults (off)", () => {
	it("requires resource, rejects unknown scopes and port drift", async () => {
		const h = harness();
		await addClient(h, { clientId: "c1", redirectUris: [LOOPBACK] });
		const noResource = await authorize(h, "c1", { redirect_uri: LOOPBACK, resource: undefined });
		expect(noResource.res.success).toBe(false);
		const badScope = await authorize(h, "c1", { redirect_uri: LOOPBACK, scope: "mcp:read nope" });
		expect(badScope.res.success).toBe(false);
		if (!badScope.res.success) expect(badScope.res.error.code).toBe("INVALID_SCOPE");
		const port = await authorize(h, "c1", { redirect_uri: "http://127.0.0.1:6000/cb" });
		expect(port.res.success).toBe(false);
		if (!port.res.success) expect(port.res.error.code).toBe("INVALID_REDIRECT_URI");
	});
});

describe("optionalResource", () => {
	it("defaults to the sole configured resource at authorize and token", async () => {
		const h = harness({ optionalResource: true });
		await addClient(h, { clientId: "c1" });
		const res = await fullFlow(h, "c1", { resource: undefined, scope: "mcp:read" });
		expect(res.success).toBe(true);
		if (res.success) expect(decodePayload(res.data.access_token).aud).toBe(RESOURCE);
	});

	it("is invalid_target when more than one resource is configured", async () => {
		const h = harness(
			{ optionalResource: true },
			{ allowedResources: [RESOURCE, "https://other.theauth.test"] },
		);
		await addClient(h, { clientId: "c1" });
		const { res } = await authorize(h, "c1", { resource: undefined });
		expect(res.success).toBe(false);
		if (!res.success) expect(res.error.code).toBe("INVALID_TARGET");
	});
});

describe("dropUnknownScopes", () => {
	it("drops unknown scopes and reports the granted scope", async () => {
		const h = harness({ dropUnknownScopes: true });
		await addClient(h, { clientId: "c1" });
		const res = await fullFlow(h, "c1", { scope: "mcp:read bogus:thing" });
		expect(res.success).toBe(true);
		if (res.success) expect(res.data.scope).toBe("mcp:read");
	});

	it("is invalid_scope when nothing requested survives", async () => {
		const h = harness({ dropUnknownScopes: true });
		await addClient(h, { clientId: "c1" });
		const { res } = await authorize(h, "c1", { scope: "bogus:a bogus:b" });
		expect(res.success).toBe(false);
		if (!res.success) expect(res.error.code).toBe("INVALID_SCOPE");
	});
});

describe("loopbackAnyPort", () => {
	it("ignores the port for registered 127.0.0.1 and [::1] redirects only", async () => {
		const h = harness({ loopbackAnyPort: true });
		await addClient(h, {
			clientId: "c1",
			redirectUris: [LOOPBACK, "http://[::1]:7000/cb", "http://localhost:8000/cb", REDIRECT],
		});
		const ok = await authorize(h, "c1", { redirect_uri: "http://127.0.0.1:61234/cb" });
		expect(ok.res.success).toBe(true);
		const v6 = await authorize(h, "c1", { redirect_uri: "http://[::1]:1/cb" });
		expect(v6.res.success).toBe(true);
		const path = await authorize(h, "c1", { redirect_uri: "http://127.0.0.1:61234/other" });
		expect(path.res.success).toBe(false);
		const scheme = await authorize(h, "c1", { redirect_uri: "https://127.0.0.1:61234/cb" });
		expect(scheme.res.success).toBe(false);
		const host = await authorize(h, "c1", { redirect_uri: "http://127.0.0.2:5000/cb" });
		expect(host.res.success).toBe(false);
		const localhost = await authorize(h, "c1", { redirect_uri: "http://localhost:9999/cb" });
		expect(localhost.res.success).toBe(false);
		const remote = await authorize(h, "c1", {
			redirect_uri: "https://app.theauth.test:444/callback",
		});
		expect(remote.res.success).toBe(false);
	});

	it("matches localhost only when loopbackAllowLocalhost is set", async () => {
		const h = harness({ loopbackAnyPort: true, loopbackAllowLocalhost: true });
		await addClient(h, { clientId: "c1", redirectUris: ["http://localhost:8000/cb"] });
		const ok = await authorize(h, "c1", { redirect_uri: "http://localhost:9999/cb" });
		expect(ok.res.success).toBe(true);
	});

	it("completes the token exchange with the actual redirect URI", async () => {
		const h = harness({ loopbackAnyPort: true });
		await addClient(h, { clientId: "c1", redirectUris: [LOOPBACK] });
		const res = await fullFlow(h, "c1", { redirect_uri: "http://127.0.0.1:50000/cb" });
		expect(res.success).toBe(true);
	});
});

describe("pathAudience", () => {
	const CONFIGURED = "https://mcp.theauth.test/mcp";

	it("matches modulo trailing slash and path prefix, issuing the canonical aud", async () => {
		const h = harness(
			{ pathAudience: true },
			{ allowedResources: [CONFIGURED], resource: CONFIGURED },
		);
		await addClient(h, { clientId: "c1" });
		for (const requested of [`${CONFIGURED}/`, `${CONFIGURED}/tools/list`, CONFIGURED]) {
			const res = await fullFlow(h, "c1", { resource: requested, scope: "mcp:read" });
			expect(res.success).toBe(true);
			if (res.success) expect(decodePayload(res.data.access_token).aud).toBe(CONFIGURED);
		}
	});

	it("rejects a sibling path, another origin and query strings that escape the prefix", async () => {
		const h = harness(
			{ pathAudience: true },
			{ allowedResources: [CONFIGURED], resource: CONFIGURED },
		);
		await addClient(h, { clientId: "c1" });
		for (const requested of [
			"https://mcp.theauth.test/mcpx",
			"https://evil.test/mcp",
			"https://mcp.theauth.test/other",
			"http://mcp.theauth.test/mcp",
		]) {
			const { res } = await authorize(h, "c1", { resource: requested });
			expect(res.success).toBe(false);
			if (!res.success) expect(res.error.code).toBe("INVALID_TARGET");
		}
	});

	it("stays exact when the option is off", async () => {
		const h = harness(undefined, { allowedResources: [CONFIGURED], resource: CONFIGURED });
		await addClient(h, { clientId: "c1" });
		const { res } = await authorize(h, "c1", { resource: `${CONFIGURED}/` });
		expect(res.success).toBe(false);
	});
});

describe("step-up upgrade URL", () => {
	it("points at the real authorization endpoint", async () => {
		const h = harness();
		const response = h.mcp.buildStepUpResponse({
			currentScopes: ["mcp:read"],
			requiredScopes: ["mcp:write"],
			resource: RESOURCE,
		});
		const body = (await response.json()) as { upgrade_url: string };
		const url = new URL(body.upgrade_url);
		expect(`${url.origin}${url.pathname}`).toBe(h.mcp.getMetadata().authorization_endpoint);
		expect(url.searchParams.get("scope")).toBe("mcp:write");
		expect(url.searchParams.get("resource")).toBe(RESOURCE);
	});
});
