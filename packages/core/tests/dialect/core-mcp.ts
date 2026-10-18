import { eq } from "drizzle-orm";
import { describe, expect, it } from "vitest";
import {
	agents,
	oauthAccessTokens,
	oauthAuthorizationCodes,
	oauthClients,
} from "../../src/db/schema.js";
import { createInMemoryJtiDenylist } from "../../src/mcp/memory-stores.js";
import { createMcpModule } from "../../src/mcp/server.js";
import type { McpAuthModule, McpTokenResponse } from "../../src/mcp/types.js";
import { computeS256Challenge, generateSecureToken } from "../../src/mcp/utils.js";
import type { TheAuth } from "../../src/theauth.js";
import type { CoreBooter } from "./core-boot.js";

const BASE_URL = "https://auth.theauth.test/api/auth";
const REDIRECT = "https://app.theauth.test/callback";
const RESOURCE = "https://mcp.theauth.test";

/** The MCP server on the database stores that ship in core (`createMcpModule({ auth, ... })`), so the whole flow runs through the dialect. */
function mcpOnDatabase(auth: TheAuth, userId: string): McpAuthModule {
	return createMcpModule({
		auth,
		config: {
			enabled: true,
			issuer: "https://auth.theauth.test",
			baseUrl: BASE_URL,
			signingSecret: "dialect-mcp-signing-secret-at-least-32-chars!!",
			resource: RESOURCE,
			scopes: ["openid", "offline_access", "mcp:read"],
			jtiDenylist: createInMemoryJtiDenylist(),
		},
		resolveUserId: async () => userId,
	});
}

function authorizeRequest(clientId: string, challenge: string): Request {
	const url = new URL(`${BASE_URL}/mcp/authorize`);
	const params = {
		response_type: "code",
		client_id: clientId,
		redirect_uri: REDIRECT,
		scope: "openid offline_access",
		state: "st",
		code_challenge: challenge,
		code_challenge_method: "S256",
		resource: RESOURCE,
	};
	for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v);
	return new Request(url.toString());
}

function formRequest(path: string, body: Record<string, string>): Request {
	return new Request(`${BASE_URL}${path}`, {
		method: "POST",
		headers: { "Content-Type": "application/x-www-form-urlencoded" },
		body: new URLSearchParams(body).toString(),
	});
}

async function register(mcp: McpAuthModule): Promise<string> {
	const reg = await mcp.registerClient({
		redirect_uris: [REDIRECT],
		token_endpoint_auth_method: "none",
		grant_types: ["authorization_code", "refresh_token"],
		response_types: ["code"],
		client_name: "Dialect Client",
		scope: "openid offline_access",
	});
	if (!reg.success) throw new Error(reg.error.message);
	return reg.data.client_id;
}

/** Authorization code + PKCE for `clientId`, returning the token response. */
async function codeGrant(mcp: McpAuthModule, clientId: string): Promise<McpTokenResponse> {
	const verifier = generateSecureToken(43);
	const authz = await mcp.authorize(
		authorizeRequest(clientId, await computeS256Challenge(verifier)),
	);
	if (!authz.success) throw new Error(authz.error.message);
	const res = await mcp.token(
		formRequest("/mcp/token", {
			grant_type: "authorization_code",
			code: authz.data.code,
			redirect_uri: REDIRECT,
			client_id: clientId,
			code_verifier: verifier,
			resource: RESOURCE,
		}),
	);
	if (!res.success) throw new Error(res.error.message);
	return res.data;
}

function claimsOf(token: string): Record<string, unknown> {
	const part = token.split(".")[1] ?? "";
	return JSON.parse(atob(part.replace(/-/g, "+").replace(/_/g, "/"))) as Record<string, unknown>;
}

export function defineMcpCoreTests(booter: CoreBooter): void {
	describe("MCP OAuth stores", () => {
		it("registers a client, spends a code once, issues and revokes tokens", async () => {
			const { auth } = await booter.boot();
			const user = await auth.user.create({ email: "mcp@example.com" });
			const mcp = mcpOnDatabase(auth, user.id);

			const clientId = await register(mcp);
			const stored = await auth.db
				.select()
				.from(oauthClients)
				.where(eq(oauthClients.clientId, clientId));
			expect(stored[0]?.redirectUris).toEqual([REDIRECT]);
			expect(stored[0]?.disabled).toBe(false);
			expect(stored[0]?.scope).toBe("openid offline_access");
			expect(stored[0]?.agentId).toBeNull();

			const verifier = generateSecureToken(43);
			const challenge = await computeS256Challenge(verifier);
			const authz = await mcp.authorize(authorizeRequest(clientId, challenge));
			if (!authz.success) throw new Error(authz.error.message);
			const [codeRow] = await auth.db.select().from(oauthAuthorizationCodes);
			expect(codeRow?.expiresAt.getTime()).toBeGreaterThan(Date.now());

			const exchange = () =>
				mcp.token(
					formRequest("/mcp/token", {
						grant_type: "authorization_code",
						code: authz.data.code,
						redirect_uri: REDIRECT,
						client_id: clientId,
						code_verifier: verifier,
						resource: RESOURCE,
					}),
				);
			const [a, b] = await Promise.all([exchange(), exchange()]);
			expect([a.success, b.success].filter(Boolean)).toHaveLength(1);
			const issued = a.success ? a.data : b.success ? b.data : null;
			if (!issued) throw new Error("no token issued");
			expect((await exchange()).success).toBe(false);
			expect(await auth.db.select().from(oauthAuthorizationCodes)).toHaveLength(0);

			const tokens = await auth.db.select().from(oauthAccessTokens);
			expect(tokens).toHaveLength(1);
			expect(tokens[0]?.accessTokenExpiresAt.getTime()).toBeGreaterThan(Date.now());
			expect(tokens[0]?.jti).toBeTruthy();
			expect(tokens[0]?.tokenType).toBe("Bearer");
			expect((await mcp.validateToken(issued.access_token)).success).toBe(true);

			const revoked = await mcp.revoke(
				formRequest("/mcp/revoke", {
					token: issued.access_token,
					token_type_hint: "access_token",
					client_id: clientId,
				}),
			);
			expect(revoked.success).toBe(true);
			expect((await mcp.validateToken(issued.access_token)).success).toBe(false);
			expect(await auth.db.select().from(oauthAccessTokens)).toHaveLength(0);
		});

		it("rotates refresh tokens in a database family and revokes the family on reuse", async () => {
			const { auth } = await booter.boot();
			const user = await auth.user.create({ email: "mcp-refresh@example.com" });
			const mcp = mcpOnDatabase(auth, user.id);
			const clientId = await register(mcp);
			const first = await codeGrant(mcp, clientId);
			const refresh = (token: string) =>
				mcp.token(
					formRequest("/mcp/token", {
						grant_type: "refresh_token",
						refresh_token: token,
						client_id: clientId,
					}),
				);
			const rotated = await refresh(first.refresh_token ?? "");
			if (!rotated.success) throw new Error(rotated.error.message);
			expect((await refresh(first.refresh_token ?? "")).success).toBe(false);
			expect((await refresh(rotated.data.refresh_token ?? "")).success).toBe(false);
		});

		it("binds a client to an agent, stamps agent_id, and clears the binding with the agent", async () => {
			const { auth } = await booter.boot();
			const user = await auth.user.create({ email: "mcp-bind@example.com" });
			const mcp = mcpOnDatabase(auth, user.id);
			const agent = await auth.agent.create({
				ownerId: user.id,
				name: "bound-bot",
				type: "autonomous",
				permissions: [],
			});
			const clientId = await register(mcp);
			await mcp.clients.bindAgent(clientId, agent.id);
			expect(await mcp.clients.agentFor(clientId)).toBe(agent.id);

			const issued = await codeGrant(mcp, clientId);
			expect(claimsOf(issued.access_token).agent_id).toBe(agent.id);

			await mcp.clients.unbindAgent(clientId);
			expect(await mcp.clients.agentFor(clientId)).toBeNull();
			await mcp.clients.bindAgent(clientId, agent.id);
			await auth.db.delete(agents).where(eq(agents.id, agent.id));
			expect(await mcp.clients.agentFor(clientId)).toBeNull();
		});
	});
}
