import { eq } from "drizzle-orm";
import { describe, expect, it } from "vitest";
import type { Database } from "../../src/db/database.js";
import { oauthAccessTokens, oauthAuthorizationCodes, oauthClients } from "../../src/db/schema.js";
import { createInMemoryJtiDenylist } from "../../src/mcp/memory-stores.js";
import { createMcpModule } from "../../src/mcp/server.js";
import type { McpAccessToken, McpClient } from "../../src/mcp/types.js";
import { computeS256Challenge, generateSecureToken } from "../../src/mcp/utils.js";
import { createTokenFamilyStore } from "../../src/session/token-family.js";
import type { CoreBooter } from "./core-boot.js";

const BASE_URL = "https://auth.theauth.test/api/auth";
const REDIRECT = "https://app.theauth.test/callback";
const RESOURCE = "https://mcp.theauth.test";

/** MCP OAuth stores backed by the theauth_oauth_* tables, so the flow runs through the dialect. */
function mcpOnDatabase(db: Database, userId: string) {
	const toClient = (row: typeof oauthClients.$inferSelect): McpClient => ({
		clientId: row.clientId,
		clientSecret: row.clientSecret,
		clientName: row.clientName,
		clientUri: row.clientUri,
		logoUri: null,
		redirectUris: row.redirectUris,
		grantTypes: row.grantTypes,
		responseTypes: row.responseTypes,
		tokenEndpointAuthMethod: row.tokenEndpointAuthMethod,
		scope: null,
		contacts: null,
		tosUri: null,
		policyUri: null,
		softwareId: null,
		softwareVersion: null,
		clientType: row.type,
		disabled: row.disabled,
		userId: null,
		createdAt: row.createdAt,
		updatedAt: row.updatedAt,
	});
	const toToken = (row: typeof oauthAccessTokens.$inferSelect): McpAccessToken => ({
		accessToken: row.accessToken,
		refreshToken: row.refreshToken,
		tokenType: "Bearer",
		expiresIn: 3600,
		scope: row.scopes.split(" "),
		clientId: row.clientId,
		userId: row.userId,
		resource: row.resource,
		expiresAt: row.accessTokenExpiresAt,
		createdAt: row.createdAt,
	});

	return createMcpModule({
		config: {
			enabled: true,
			issuer: "https://auth.theauth.test",
			baseUrl: BASE_URL,
			signingSecret: "dialect-mcp-signing-secret-at-least-32-chars!!",
			resource: RESOURCE,
			scopes: ["openid", "offline_access", "mcp:read"],
			jtiDenylist: createInMemoryJtiDenylist(),
			tokenFamilies: createTokenFamilyStore(db),
		},
		storeClient: async (c) => {
			await db.insert(oauthClients).values({
				id: `oc_${c.clientId}`,
				clientId: c.clientId,
				clientSecret: c.clientSecret,
				clientName: c.clientName,
				clientUri: c.clientUri,
				redirectUris: c.redirectUris,
				grantTypes: c.grantTypes,
				responseTypes: c.responseTypes,
				tokenEndpointAuthMethod: c.tokenEndpointAuthMethod,
				type: c.clientType,
				disabled: c.disabled,
				createdAt: c.createdAt,
				updatedAt: c.updatedAt,
			});
		},
		findClient: async (clientId) => {
			const rows = await db.select().from(oauthClients).where(eq(oauthClients.clientId, clientId));
			return rows[0] ? toClient(rows[0]) : null;
		},
		storeAuthorizationCode: async (c) => {
			await db.insert(oauthAuthorizationCodes).values({
				id: `ac_${c.code.slice(0, 24)}`,
				code: c.code,
				clientId: c.clientId,
				userId: c.userId,
				redirectUri: c.redirectUri,
				scopes: c.scope.join(" "),
				codeChallenge: c.codeChallenge,
				codeChallengeMethod: c.codeChallengeMethod,
				resource: c.resource,
				expiresAt: c.expiresAt,
				createdAt: c.createdAt,
			});
		},
		// One DELETE ... RETURNING: of two concurrent callers only one gets the row.
		consumeAuthorizationCode: async (code) => {
			const rows = await db
				.delete(oauthAuthorizationCodes)
				.where(eq(oauthAuthorizationCodes.code, code))
				.returning();
			const row = rows[0];
			if (!row) return null;
			return {
				code: row.code,
				clientId: row.clientId,
				userId: row.userId,
				redirectUri: row.redirectUri,
				scope: row.scopes.split(" "),
				codeChallenge: row.codeChallenge ?? "",
				codeChallengeMethod: "S256",
				resource: row.resource,
				expiresAt: row.expiresAt,
				createdAt: row.createdAt,
			};
		},
		storeToken: async (t) => {
			await db.insert(oauthAccessTokens).values({
				id: `at_${t.accessToken.slice(0, 24)}`,
				accessToken: t.accessToken,
				refreshToken: t.refreshToken,
				clientId: t.clientId,
				userId: t.userId,
				scopes: t.scope.join(" "),
				resource: t.resource,
				accessTokenExpiresAt: t.expiresAt,
				refreshTokenExpiresAt: t.refreshToken ? new Date(t.expiresAt.getTime() + 86_400_000) : null,
				createdAt: t.createdAt,
			});
		},
		findTokenByRefreshToken: async (rt) => {
			const rows = await db
				.select()
				.from(oauthAccessTokens)
				.where(eq(oauthAccessTokens.refreshToken, rt));
			return rows[0] ? toToken(rows[0]) : null;
		},
		revokeToken: async (accessToken) => {
			await db.delete(oauthAccessTokens).where(eq(oauthAccessTokens.accessToken, accessToken));
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

export function defineMcpCoreTests(booter: CoreBooter): void {
	describe("MCP OAuth stores", () => {
		it("registers a client, spends a code once, issues and revokes tokens", async () => {
			const { auth } = await booter.boot();
			const user = await auth.user.create({ email: "mcp@example.com" });
			const mcp = mcpOnDatabase(auth.db, user.id);

			const reg = await mcp.registerClient({
				redirect_uris: [REDIRECT],
				token_endpoint_auth_method: "none",
				grant_types: ["authorization_code", "refresh_token"],
				response_types: ["code"],
				client_name: "Dialect Client",
				scope: "openid offline_access",
			});
			if (!reg.success) throw new Error(reg.error.message);
			const clientId = reg.data.client_id;
			const stored = await auth.db
				.select()
				.from(oauthClients)
				.where(eq(oauthClients.clientId, clientId));
			expect(stored[0]?.redirectUris).toEqual([REDIRECT]);
			expect(stored[0]?.disabled).toBe(false);

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
	});
}
