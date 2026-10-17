import { createHmac } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as schema from "../../core/src/db/schema.js";
import { createMcpModule } from "../../core/src/mcp/server.js";
import type { TheAuth } from "../../core/src/theauth.js";
import { createTheAuth } from "../../core/src/theauth.js";
import { createGateway } from "../src/gateway.js";
import { buildMcpValidator } from "../src/init.js";

const ISSUER = "https://auth.example.test";
const RESOURCE = "https://mcp.example.test/mcp";
const SECRET = "gateway-test-signing-secret-32-chars-minimum!!";
const UPSTREAM = "http://upstream.test";

const auth = createMcpModule({
	config: {
		enabled: true,
		issuer: ISSUER,
		baseUrl: ISSUER,
		signingSecret: SECRET,
		scopes: ["mcp:read", "mcp:write"],
	},
	storeClient: async () => undefined,
	findClient: async () => null,
	storeAuthorizationCode: async () => undefined,
	consumeAuthorizationCode: async () => null,
	storeToken: async () => undefined,
	findTokenByRefreshToken: async () => null,
	revokeToken: async () => undefined,
	resolveUserId: async () => null,
});

function b64(value: unknown): string {
	return Buffer.from(JSON.stringify(value)).toString("base64url");
}

/** HS256 access token, signed by hand so the test needs no JWT library. */
async function mint(
	opts: { aud?: string; scope?: string; agentId?: string; secret?: string } = {},
): Promise<string> {
	const now = Math.floor(Date.now() / 1000);
	const signingInput = `${b64({ alg: "HS256", typ: "JWT" })}.${b64({
		iss: ISSUER,
		sub: "user-1",
		aud: opts.aud ?? RESOURCE,
		jti: crypto.randomUUID(),
		iat: now,
		exp: now + 300,
		client_id: "client-1",
		scope: opts.scope ?? "mcp:read",
		...(opts.agentId ? { agent_id: opts.agentId } : {}),
	})}`;
	const sig = createHmac("sha256", opts.secret ?? SECRET)
		.update(signingInput)
		.digest("base64url");
	return `${signingInput}.${sig}`;
}

function req(path: string, token?: string, init: RequestInit = {}): Request {
	const headers = new Headers(init.headers);
	if (token) headers.set("Authorization", `Bearer ${token}`);
	return new Request(`http://gw.test${path}`, { ...init, headers });
}

describe("gateway MCP mode", () => {
	let theauth: TheAuth;
	let fetchSpy: ReturnType<typeof vi.spyOn>;
	let seen: Request | null;

	beforeEach(async () => {
		theauth = await createTheAuth({
			database: { provider: "sqlite", url: ":memory:" },
			agents: {
				enabled: true,
				maxPerUser: 10,
				defaultPermissions: [],
				auditAll: true,
				tokenExpiry: "24h",
			},
		});
		theauth.db
			.insert(schema.users)
			.values({
				id: "user-1",
				email: "a@b.test",
				name: "U",
				createdAt: new Date(),
				updatedAt: new Date(),
			})
			.run();
		seen = null;
		fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation((input) => {
			seen = input as Request;
			return Promise.resolve(
				new Response('{"jsonrpc":"2.0"}', { headers: { "Content-Type": "application/json" } }),
			);
		});
	});
	afterEach(() => fetchSpy.mockRestore());

	const make = (extra: Partial<Parameters<typeof createGateway>[0]> = {}) =>
		createGateway({ upstream: UPSTREAM, theauth, mcp: { auth, resource: RESOURCE }, ...extra });

	it("serves RFC 9728 metadata for the upstream resource without auth", async () => {
		const gw = make();
		for (const path of [
			"/.well-known/oauth-protected-resource",
			"/.well-known/oauth-protected-resource/mcp",
		]) {
			const res = await gw.handleRequest(req(path));
			expect(res.status).toBe(200);
			const doc = (await res.json()) as { resource: string; authorization_servers: string[] };
			expect(doc.resource).toBe(RESOURCE);
			expect(doc.authorization_servers).toEqual([ISSUER]);
		}
		expect(fetchSpy).not.toHaveBeenCalled();
	});

	it("401 carries resource_metadata and never reaches the upstream", async () => {
		const res = await make().handleRequest(req("/mcp", undefined, { method: "POST", body: "{}" }));
		expect(res.status).toBe(401);
		const challenge = res.headers.get("www-authenticate") ?? "";
		expect(challenge).toContain(
			'resource_metadata="https://mcp.example.test/.well-known/oauth-protected-resource/mcp"',
		);
		expect(fetchSpy).not.toHaveBeenCalled();
	});

	it("rejects tokens minted for another audience", async () => {
		const res = await make().handleRequest(req("/mcp", await mint({ aud: "https://other.test" })));
		expect(res.status).toBe(401);
		expect(fetchSpy).not.toHaveBeenCalled();
	});

	it("rejects tokens signed with a different key", async () => {
		const res = await make().handleRequest(
			req("/mcp", await mint({ secret: "another-secret-another-secret-another!!" })),
		);
		expect(res.status).toBe(401);
	});

	it("proxies a valid token and strips it before the upstream", async () => {
		const res = await make().handleRequest(
			req("/mcp", await mint(), { method: "POST", body: "{}" }),
		);
		expect(res.status).toBe(200);
		expect(seen?.headers.get("authorization")).toBeNull();
		expect(new URL(seen?.url ?? "").pathname).toBe("/mcp");
	});

	it("enforces gateway wide and per policy scopes with a 403", async () => {
		const gw = make({
			mcp: { auth, resource: RESOURCE, requiredScopes: ["mcp:read"] },
			policies: [{ path: "/mcp/admin/**", requiredScopes: ["mcp:write"] }],
		});
		const token = await mint({ scope: "mcp:read" });
		expect((await gw.handleRequest(req("/mcp", token))).status).toBe(200);
		const denied = await gw.handleRequest(req("/mcp/admin/x", token));
		expect(denied.status).toBe(403);
		expect(denied.headers.get("www-authenticate")).toContain("insufficient_scope");
		expect(
			(await gw.handleRequest(req("/mcp/admin/x", await mint({ scope: "mcp:read mcp:write" }))))
				.status,
		).toBe(200);
	});

	it("applies agent permission policies to the agent named in the token", async () => {
		const agent = await theauth.agent.create({
			ownerId: "user-1",
			name: "a",
			type: "autonomous",
			permissions: [{ resource: "tools", actions: ["call"] }],
		});
		const gw = make({
			policies: [{ path: "/mcp", requiredPermissions: [{ resource: "tools", actions: ["call"] }] }],
		});
		expect((await gw.handleRequest(req("/mcp", await mint({ agentId: agent.id })))).status).toBe(
			200,
		);
		// No agent claim: a permission policy fails closed.
		expect((await gw.handleRequest(req("/mcp", await mint()))).status).toBe(403);
		const other = await theauth.agent.create({
			ownerId: "user-1",
			name: "b",
			type: "autonomous",
			permissions: [],
		});
		expect((await gw.handleRequest(req("/mcp", await mint({ agentId: other.id })))).status).toBe(
			403,
		);
	});

	it("refuses browser origins that are not allowed (DNS rebinding)", async () => {
		const gw = make();
		const res = await gw.handleRequest(
			req("/mcp", await mint(), { headers: { Origin: "https://evil.test" } }),
		);
		expect(res.status).toBe(403);
		const ok = make({ cors: { origins: ["https://app.example.test"] } });
		const allowed = await ok.handleRequest(
			req("/mcp", await mint(), { headers: { Origin: "https://app.example.test" } }),
		);
		expect(allowed.status).toBe(200);
		expect(allowed.headers.get("access-control-expose-headers")).toContain("WWW-Authenticate");
	});

	it("refuses requiredScopes policies when MCP mode is off", () => {
		expect(() =>
			createGateway({
				upstream: UPSTREAM,
				theauth,
				policies: [{ path: "/**", requiredScopes: ["x"] }],
			}),
		).toThrow(/mcp option/);
	});

	it("the CLI validator accepts tokens signed with the shared secret", async () => {
		const gw = createGateway({
			upstream: UPSTREAM,
			theauth,
			mcp: {
				auth: buildMcpValidator({ issuer: ISSUER, signingSecret: SECRET }),
				resource: RESOURCE,
			},
		});
		expect((await gw.handleRequest(req("/mcp", await mint()))).status).toBe(200);
		expect(
			(await gw.handleRequest(req("/mcp", await mint({ aud: "https://x.test" })))).status,
		).toBe(401);
	});
});
