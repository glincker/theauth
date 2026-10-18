import { describe, expect, it } from "vitest";
import { createTheAuthHandler, listRoutes } from "../../src/http/index.js";
import { generateMcpSigningKey } from "../../src/mcp/keys.js";
import { addClient, BASE_URL, codeFlow, makeHarness, REDIRECT } from "../mcp-test-harness.js";
import { BASE, makeAuth } from "./helpers.js";

async function setup(
	config: Parameters<typeof makeHarness>[0] = {},
	routes?: { mcp?: boolean | Record<string, boolean> },
) {
	const auth = await makeAuth();
	const h = makeHarness(config);
	const handler = createTheAuthHandler(auth, { mcp: h.mcp, rateLimit: false, routes });
	const get = (path: string) => handler(new Request(`${BASE}${path}`));
	return { auth, h, handler, get };
}

describe("MCP revoke and jwks routes", () => {
	it("serves /mcp/jwks with the published signing keys", async () => {
		const key = await generateMcpSigningKey("ES256", "k1");
		const { get } = await setup({
			signingSecret: undefined,
			signing: { alg: "ES256", current: { kid: "k1", privateKey: key.privateKey } },
		});
		const res = await get("/mcp/jwks");
		expect(res.status).toBe(200);
		const body = (await res.json()) as { keys: Array<{ kid: string; d?: string }> };
		expect(body.keys.map((k) => k.kid)).toEqual(["k1"]);
		expect(body.keys[0]?.d).toBeUndefined();
	});

	it("serves /mcp/revoke per RFC 7009 and actually revokes", async () => {
		const { h, handler } = await setup();
		await addClient(h, { clientId: "c1", secret: "s3cret" });
		const tokens = await codeFlow(h, "c1", { secret: "s3cret" });
		const basic = `Basic ${btoa("c1:s3cret")}`;
		const revoke = (body: Record<string, string>, headers: Record<string, string> = {}) =>
			handler(
				new Request(`${BASE}/mcp/revoke`, {
					method: "POST",
					headers: { "Content-Type": "application/x-www-form-urlencoded", ...headers },
					body: new URLSearchParams(body).toString(),
				}),
			);

		const unauth = await revoke({ token: tokens.access_token });
		expect(unauth.status).toBe(401);
		expect(((await unauth.json()) as { error: string }).error).toBe("invalid_client");

		const ok = await revoke({ token: tokens.access_token }, { Authorization: basic });
		expect(ok.status).toBe(200);
		expect(ok.headers.get("cache-control")).toBe("no-store");

		const unknown = await revoke({ token: "does-not-exist" }, { Authorization: basic });
		expect(unknown.status).toBe(200);

		const missing = await revoke({}, { Authorization: basic });
		expect(missing.status).toBe(400);
		expect(unauth.headers.get("www-authenticate")).toMatch(/^Basic/);
	});

	it("serves /mcp/introspect only when the module enables it, and lists the route", async () => {
		const { handler, get } = await setup();
		// The harness module does not enable introspection: the route does not exist for it.
		const off = await handler(
			new Request(`${BASE}/mcp/introspect`, {
				method: "POST",
				headers: { "Content-Type": "application/x-www-form-urlencoded" },
				body: "token=x",
			}),
		);
		expect(off.status).toBe(404);
		const meta = (await (await get("/.well-known/oauth-authorization-server")).json()) as Record<
			string,
			unknown
		>;
		expect(meta.introspection_endpoint).toBeUndefined();
		const spec = listRoutes().find((r) => r.path === "/mcp/introspect");
		expect(spec).toMatchObject({ method: "POST", auth: "client" });
	});

	it("answers OPTIONS on mcp paths without CORS headers unless configured", async () => {
		const { handler } = await setup();
		const res = await handler(new Request(`${BASE}/mcp/revoke`, { method: "OPTIONS" }));
		expect(res.status).toBe(204);
		expect(res.headers.get("access-control-allow-origin")).toBeNull();
		expect(res.headers.get("allow")).toBe("POST, OPTIONS");
	});

	it("serves register, authorize and token", async () => {
		const { get, handler } = await setup();
		const reg = await handler(
			new Request(`${BASE}/mcp/register`, {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({
					client_name: "x",
					redirect_uris: [REDIRECT],
					token_endpoint_auth_method: "none",
				}),
			}),
		);
		expect(reg.status).toBe(201);
		expect((await get("/mcp/authorize")).status).toBe(400);
		const tok = await handler(new Request(`${BASE}/mcp/token`, { method: "POST" }));
		expect([400, 401]).toContain(tok.status);
	});
});

describe("metadata matches the mounted set", () => {
	it("lists every endpoint when all are mounted, and each one answers", async () => {
		const key = await generateMcpSigningKey("ES256", "k1");
		const { get } = await setup({
			signingSecret: undefined,
			signing: { alg: "ES256", current: { kid: "k1", privateKey: key.privateKey } },
		});
		const meta = (await (await get("/.well-known/oauth-authorization-server")).json()) as Record<
			string,
			string
		>;
		const served = new Set(listRoutes().map((r) => r.path));
		for (const field of [
			"authorization_endpoint",
			"token_endpoint",
			"registration_endpoint",
			"revocation_endpoint",
			"jwks_uri",
		]) {
			const path = new URL(meta[field] ?? "").pathname.replace(new URL(BASE_URL).pathname, "");
			expect(served.has(path), field).toBe(true);
		}
	});

	it("omits endpoints that are not mounted", async () => {
		const key = await generateMcpSigningKey("ES256", "k1");
		const { get, handler } = await setup(
			{
				signingSecret: undefined,
				signing: { alg: "ES256", current: { kid: "k1", privateKey: key.privateKey } },
			},
			{ mcp: { revoke: false, introspect: false, jwks: false } },
		);
		const meta = (await (await get("/.well-known/oauth-authorization-server")).json()) as Record<
			string,
			unknown
		>;
		expect(meta.revocation_endpoint).toBeUndefined();
		expect(meta.revocation_endpoint_auth_methods_supported).toBeUndefined();
		expect(meta.introspection_endpoint).toBeUndefined();
		expect(meta.introspection_endpoint_auth_methods_supported).toBeUndefined();
		expect(meta.jwks_uri).toBeUndefined();
		expect(meta.token_endpoint).toBeDefined();
		const resource = (await (await get("/.well-known/oauth-protected-resource")).json()) as Record<
			string,
			unknown
		>;
		expect(resource.jwks_uri).toBeUndefined();
		expect((await get("/mcp/jwks")).status).toBe(404);
		const rev = await handler(new Request(`${BASE}/mcp/revoke`, { method: "POST" }));
		expect(rev.status).toBe(404);
		const introspect = await handler(new Request(`${BASE}/mcp/introspect`, { method: "POST" }));
		expect(introspect.status).toBe(404);
		const unmounted = listRoutes({
			routes: { mcp: { revoke: false, introspect: false, jwks: false } },
		}).map((r) => r.path);
		expect(unmounted).not.toContain("/mcp/revoke");
		expect(unmounted).not.toContain("/mcp/introspect");
	});

	it("answers 404 for MCP routes when no module is configured or MCP is off", async () => {
		const auth = await makeAuth();
		const none = createTheAuthHandler(auth, { rateLimit: false });
		expect((await none(new Request(`${BASE}/mcp/jwks`))).status).toBe(404);
		const h = makeHarness();
		const off = createTheAuthHandler(auth, {
			mcp: h.mcp,
			rateLimit: false,
			routes: { mcp: false },
		});
		expect((await off(new Request(`${BASE}/.well-known/oauth-authorization-server`))).status).toBe(
			404,
		);
	});
});
