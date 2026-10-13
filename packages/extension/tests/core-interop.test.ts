/**
 * End to end: the extension package against the in-process MCP authorization
 * server from core. The fake identity follows the authorize redirect by calling
 * the server directly, as a browser would.
 */

import { describe, expect, it } from "vitest";
import { createDPoPClient } from "../../client/src/dpop.js";
import type { McpPrincipal } from "../../core/src/mcp/require-mcp-auth.js";
import { createMcpModule } from "../../core/src/mcp/server.js";
import type {
	McpAccessToken,
	McpAuthModule,
	McpAuthorizationCode,
	McpClient,
	McpConfig,
} from "../../core/src/mcp/types.js";
import type { IdentityLike } from "../src/index.js";
import { createExtensionAuth, createMemoryKeyStore } from "../src/index.js";
import { fakeStorage } from "./helpers.js";

const ISSUER = "https://auth.theauth.test";
const BASE_URL = "https://auth.theauth.test/api/auth";
const SECRET = "test-signing-secret-at-least-32-chars-long!!";
const REDIRECT = "https://abcdefghijklmnop.chromiumapp.org/";
const RESOURCE = "https://mcp.theauth.test";

interface Harness {
	mcp: McpAuthModule;
	revoked: string[];
	authorizeUrls: string[];
	fetch: typeof fetch;
	identity: IdentityLike;
	clientId: string;
}

async function makeHarness(config: Partial<McpConfig> = {}): Promise<Harness> {
	const clients = new Map<string, McpClient>();
	const codes = new Map<string, McpAuthorizationCode>();
	const byRefresh = new Map<string, McpAccessToken>();
	const revoked: string[] = [];
	const mcp = createMcpModule({
		config: {
			enabled: true,
			issuer: ISSUER,
			baseUrl: BASE_URL,
			signingSecret: SECRET,
			resource: RESOURCE,
			scopes: ["mcp:read", "mcp:write"],
			...config,
		},
		storeClient: async (c) => {
			clients.set(c.clientId, c);
		},
		findClient: async (id) => clients.get(id) ?? null,
		storeAuthorizationCode: async (c) => {
			codes.set(c.code, c);
		},
		consumeAuthorizationCode: async (code) => {
			const found = codes.get(code) ?? null;
			codes.delete(code);
			return found;
		},
		storeToken: async (t) => {
			if (t.refreshToken) byRefresh.set(t.refreshToken, t);
		},
		findTokenByRefreshToken: async (rt) => byRefresh.get(rt) ?? null,
		revokeToken: async (token) => {
			revoked.push(token);
		},
		resolveUserId: async () => "user_1",
	});
	const reg = await mcp.registerClient({
		redirect_uris: [REDIRECT],
		token_endpoint_auth_method: "none",
		grant_types: ["authorization_code", "refresh_token"],
	});
	if (!reg.success) throw new Error(reg.error.message);

	const authorizeUrls: string[] = [];
	const serve = (async (input: RequestInfo | URL, init?: RequestInit) => {
		const req = new Request(input, init);
		const path = new URL(req.url).pathname;
		if (path === "/.well-known/oauth-authorization-server") return Response.json(mcp.getMetadata());
		if (path.endsWith("/mcp/token")) {
			const r = await mcp.token(req);
			if (r.success) return Response.json(r.data);
			const nonce = r.error.details?.dpopNonce;
			return Response.json(
				{ error: r.error.code.toLowerCase() },
				{ status: 400, headers: typeof nonce === "string" ? { "DPoP-Nonce": nonce } : {} },
			);
		}
		if (path.endsWith("/mcp/revoke")) {
			await mcp.revoke(req);
			return new Response(null, { status: 200 });
		}
		return new Response("not found", { status: 404 });
	}) as typeof fetch;

	const identity: IdentityLike = {
		getRedirectURL: () => REDIRECT,
		async launchWebAuthFlow({ url }) {
			authorizeUrls.push(url);
			const r = await mcp.authorize(new Request(url));
			if (!r.success) throw new Error(r.error.message);
			return r.data.redirectUri;
		},
	};
	return { mcp, revoked, authorizeUrls, fetch: serve, identity, clientId: reg.data.client_id };
}

describe("extension auth against the MCP authorization server", () => {
	it("signs in with discovery, PKCE and resource, then refreshes and signs out", async () => {
		const h = await makeHarness();
		let now = Date.now();
		const auth = createExtensionAuth({
			issuer: ISSUER,
			clientId: h.clientId,
			scopes: ["mcp:read", "offline_access"],
			resource: RESOURCE,
			identity: h.identity,
			storage: fakeStorage(),
			keyStore: createMemoryKeyStore(),
			fetch: h.fetch,
			clock: () => now,
		});

		const session = await auth.signIn();
		expect(session.tokenType).toBe("Bearer");
		expect(session.scope).toContain("mcp:read");
		const first = await auth.getAccessToken();
		expect((await h.mcp.validateToken(first)).success).toBe(true);
		const url = new URL(h.authorizeUrls[0] ?? "");
		expect(url.searchParams.get("code_challenge_method")).toBe("S256");
		expect(url.searchParams.get("resource")).toBe(RESOURCE);

		now += 2 * 3600 * 1000;
		const second = await auth.getAccessToken();
		expect(second).not.toBe(first);
		expect((await h.mcp.validateToken(second)).success).toBe(true);

		expect((await auth.signOut()).revoked).toBe(true);
		expect(await auth.getSession()).toBeNull();
	});

	it("binds tokens to the persisted DPoP key and calls a guarded resource", async () => {
		const h = await makeHarness({ dpop: { requireNonce: true } });
		const echo = (_req: Request, p: McpPrincipal) =>
			Response.json({ scheme: p.scheme, jkt: p.dpopJkt });
		const guarded = h.mcp.requireMcpAuth(echo);
		const routed = (async (input: RequestInfo | URL, init?: RequestInit) => {
			const req = new Request(input, init);
			return req.url.startsWith(RESOURCE) ? guarded(req) : h.fetch(req);
		}) as typeof fetch;

		const keyStore = createMemoryKeyStore();
		const options = {
			issuer: ISSUER,
			clientId: h.clientId,
			scopes: ["mcp:read", "offline_access"],
			resource: RESOURCE,
			identity: h.identity,
			storage: fakeStorage(),
			keyStore,
			fetch: routed,
			dpop: { module: { createDPoPClient } },
		};
		const auth = createExtensionAuth(options);
		const session = await auth.signIn();
		expect(session.tokenType).toBe("DPoP");

		const res = await auth.fetch(`${RESOURCE}/tools`);
		expect(res.status).toBe(200);
		const body = (await res.json()) as { scheme: string; jkt: string };
		expect(body.scheme).toBe("DPoP");

		// A new instance sharing the key store presents the same key.
		const again = createExtensionAuth({ ...options, storage: options.storage });
		const res2 = await again.fetch(`${RESOURCE}/tools`);
		const body2 = (await res2.json()) as { jkt: string };
		expect(body2.jkt).toBe(body.jkt);
	});
});
