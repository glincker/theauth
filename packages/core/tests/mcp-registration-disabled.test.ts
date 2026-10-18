/** `registration: { enabled: false }` turns dynamic client registration off and leaves existing clients alone. */
import { describe, expect, it } from "vitest";
import { createTheAuthHandler } from "../src/http/index.js";
import { getAuthorizationServerMetadata } from "../src/mcp/metadata.js";
import { BASE, makeAuth } from "./http/helpers.js";
import { addClient, codeFlow, makeHarness, REDIRECT } from "./mcp-test-harness.js";

const BODY = { redirect_uris: [REDIRECT], token_endpoint_auth_method: "none" };

async function route(config: Parameters<typeof makeHarness>[0]) {
	const auth = await makeAuth();
	const h = makeHarness(config);
	const handler = createTheAuthHandler(auth, { mcp: h.mcp, rateLimit: false });
	const post = () =>
		handler(
			new Request(`${BASE}/mcp/register`, {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify(BODY),
			}),
		);
	return { h, handler, post };
}

describe("registration disabled", () => {
	it("registerClient returns REGISTRATION_DISABLED and stores nothing", async () => {
		const h = makeHarness({ registration: { enabled: false } });
		const res = await h.mcp.registerClient(BODY);
		expect(res.success).toBe(false);
		expect(!res.success && res.error.code).toBe("REGISTRATION_DISABLED");
		expect(h.clients.size).toBe(0);
	});

	it("metadata drops registration_endpoint, on the module and over HTTP", async () => {
		const { h, handler } = await route({ registration: { enabled: false } });
		expect("registration_endpoint" in h.mcp.getMetadata()).toBe(false);
		const res = await handler(new Request(`${BASE}/.well-known/oauth-authorization-server`));
		const body = (await res.json()) as Record<string, unknown>;
		expect(body.registration_endpoint).toBeUndefined();
		expect(body.authorization_endpoint).toBeDefined();
		expect(body.token_endpoint).toBeDefined();
	});

	it("POST /mcp/register answers 404 and registers nothing", async () => {
		const { h, post } = await route({ registration: { enabled: false } });
		const res = await post();
		expect(res.status).toBe(404);
		expect(h.clients.size).toBe(0);
	});

	it("pre-registered and previously stored clients still authorize", async () => {
		const h = makeHarness({
			registration: { enabled: false },
			preRegisteredClients: [{ clientId: "pre_1", redirectUris: [REDIRECT], scope: "mcp:read" }],
		});
		await new Promise((r) => setTimeout(r, 10));
		const pre = await codeFlow(h, "pre_1", { scope: "mcp:read" });
		expect(pre.access_token).toBeTruthy();

		await addClient(h, { clientId: "earlier_dcr_client" });
		const earlier = await codeFlow(h, "earlier_dcr_client");
		expect(earlier.access_token).toBeTruthy();
	});
});

describe("registration enabled (default)", () => {
	it("advertises the endpoint and registers clients, with and without the setting", async () => {
		for (const config of [{}, { registration: {} }, { registration: { enabled: true } }]) {
			const { h, post } = await route(config);
			expect(h.mcp.getMetadata().registration_endpoint).toMatch(/\/mcp\/register$/);
			const res = await post();
			expect(res.status).toBe(201);
			expect(h.clients.size).toBe(1);
		}
	});

	it("keeps registration_endpoint in the metadata builder by default", () => {
		const h = makeHarness();
		expect(h.mcp.getMetadata()).toEqual(
			expect.objectContaining({ registration_endpoint: expect.any(String) }),
		);
		expect(getAuthorizationServerMetadata).toBeTypeOf("function");
	});
});
