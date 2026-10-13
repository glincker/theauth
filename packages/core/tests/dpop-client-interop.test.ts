/**
 * Interop: the @glinr/theauth-client DPoP helper against the real MCP
 * authorization server and resource-server guard (nonce retry, ath, htu).
 */

import { describe, expect, it } from "vitest";
import { createDPoPClient } from "../../client/src/dpop.js";
import type { McpPrincipal } from "../src/mcp/require-mcp-auth.js";
import { createMcpModule } from "../src/mcp/server.js";
import type {
	McpAccessToken,
	McpAuthModule,
	McpAuthorizationCode,
	McpClient,
	McpConfig,
	McpTokenResponse,
} from "../src/mcp/types.js";
import { computeS256Challenge, generateSecureToken } from "../src/mcp/utils.js";

const ISSUER = "https://auth.theauth.test";
const BASE_URL = "https://auth.theauth.test/api/auth";
const TOKEN_URL = `${BASE_URL}/mcp/token`;
const SECRET = "test-signing-secret-at-least-32-chars-long!!";
const REDIRECT = "https://app.theauth.test/callback";
const RESOURCE = "https://mcp.theauth.test";
const RS_URL = `${RESOURCE}/tools?cursor=1`;
const USER = "user_1";

// Harness

interface Store {
	clients: Map<string, McpClient>;
	codes: Map<string, McpAuthorizationCode>;
	tokens: Map<string, McpAccessToken>;
	byRefresh: Map<string, McpAccessToken>;
}

function makeMcp(config: Partial<McpConfig> = {}): McpAuthModule {
	const store: Store = {
		clients: new Map(),
		codes: new Map(),
		tokens: new Map(),
		byRefresh: new Map(),
	};
	return createMcpModule({
		config: {
			enabled: true,
			issuer: ISSUER,
			baseUrl: BASE_URL,
			signingSecret: SECRET,
			resource: RESOURCE,
			scopes: ["mcp:read", "mcp:write"],
			dpop: {},
			...config,
		},
		storeClient: async (c) => {
			store.clients.set(c.clientId, c);
		},
		findClient: async (id) => store.clients.get(id) ?? null,
		storeAuthorizationCode: async (c) => {
			store.codes.set(c.code, c);
		},
		consumeAuthorizationCode: async (code) => {
			const found = store.codes.get(code) ?? null;
			store.codes.delete(code);
			return found;
		},
		storeToken: async (t) => {
			store.tokens.set(t.accessToken, t);
			if (t.refreshToken) store.byRefresh.set(t.refreshToken, t);
		},
		findTokenByRefreshToken: async (rt) => store.byRefresh.get(rt) ?? null,
		revokeToken: async () => {},
		resolveUserId: async () => USER,
	});
}

async function registerPublic(mcp: McpAuthModule): Promise<string> {
	const r = await mcp.registerClient({
		redirect_uris: [REDIRECT],
		token_endpoint_auth_method: "none",
		grant_types: ["authorization_code", "refresh_token"],
	});
	if (!r.success) throw new Error(r.error.message);
	return r.data.client_id;
}

/** Authorize and return the code plus the PKCE verifier. */
async function getCode(mcp: McpAuthModule, clientId: string) {
	const verifier = generateSecureToken(43);
	const url = new URL(`${BASE_URL}/mcp/authorize`);
	for (const [k, v] of Object.entries({
		response_type: "code",
		client_id: clientId,
		redirect_uri: REDIRECT,
		scope: "mcp:read offline_access",
		state: "s1",
		code_challenge: await computeS256Challenge(verifier),
		code_challenge_method: "S256",
		resource: RESOURCE,
	})) {
		url.searchParams.set(k, v);
	}
	const auth = await mcp.authorize(new Request(url));
	if (!auth.success) throw new Error(auth.error.message);
	return { code: new URL(auth.data.redirectUri).searchParams.get("code") ?? "", verifier };
}

function codeBody(clientId: string, code: string, verifier: string) {
	return {
		grant_type: "authorization_code",
		code,
		redirect_uri: REDIRECT,
		client_id: clientId,
		code_verifier: verifier,
		resource: RESOURCE,
	};
}

/** Mirrors what adapters do with a token result (status plus DPoP-Nonce header). */
function toResponse(result: Awaited<ReturnType<McpAuthModule["token"]>>): Response {
	if (result.success) return Response.json(result.data);
	const nonce = result.error.details?.dpopNonce;
	return Response.json(
		{ error: result.error.code.toLowerCase() },
		{
			status: 400,
			headers: typeof nonce === "string" ? { "DPoP-Nonce": nonce } : {},
		},
	);
}

const echo = (_req: Request, p: McpPrincipal) =>
	Response.json({ user: p.userId, scheme: p.scheme, jkt: p.dpopJkt });

describe("client DPoP helper against the MCP server", () => {
	it("completes a code exchange through the nonce challenge, then calls the resource", async () => {
		const mcp = makeMcp({ dpop: { requireNonce: true } });
		const clientId = await registerPublic(mcp);
		const { code, verifier } = await getCode(mcp, clientId);
		let tokenCalls = 0;

		const asFetch = (async (input: Request) => {
			tokenCalls++;
			return toResponse(await mcp.token(input));
		}) as unknown as typeof fetch;
		const asClient = await createDPoPClient({ fetch: asFetch });

		const res = await asClient.fetch(TOKEN_URL, {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams(codeBody(clientId, code, verifier)).toString(),
		});
		expect(res.status).toBe(200);
		expect(tokenCalls).toBe(2);
		const tokens = (await res.json()) as McpTokenResponse;
		expect(tokens.token_type).toBe("DPoP");

		const guarded = mcp.requireMcpAuth(echo);
		const rsFetch = (async (input: Request) => guarded(input)) as unknown as typeof fetch;
		const rsClient = await createDPoPClient({ prover: asClient.prover, fetch: rsFetch });
		const rs = await rsClient.fetch(RS_URL, undefined, { accessToken: tokens.access_token });
		expect(rs.status).toBe(200);
		const out = (await rs.json()) as { scheme: string; jkt: string };
		expect(out.scheme).toBe("DPoP");
		expect(out.jkt).toBe(await asClient.thumbprint());
	});

	it("a different prover is rejected at the resource server", async () => {
		const mcp = makeMcp();
		const clientId = await registerPublic(mcp);
		const { code, verifier } = await getCode(mcp, clientId);
		const asClient = await createDPoPClient({
			fetch: (async (input: Request) =>
				toResponse(await mcp.token(input))) as unknown as typeof fetch,
		});
		const res = await asClient.fetch(TOKEN_URL, {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams(codeBody(clientId, code, verifier)).toString(),
		});
		const tokens = (await res.json()) as McpTokenResponse;
		const guarded = mcp.requireMcpAuth(echo);
		const other = await createDPoPClient({
			fetch: (async (input: Request) => guarded(input)) as unknown as typeof fetch,
		});
		const rs = await other.fetch(RS_URL, undefined, { accessToken: tokens.access_token });
		expect(rs.status).toBe(401);
	});
});
