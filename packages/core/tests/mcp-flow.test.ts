/**
 * MCP OAuth 2.1 End-to-End Integration Tests
 *
 * Exercises the full OAuth 2.1 authorization code flow using in-memory
 * storage — no database required.  Each test group builds on real module
 * instances returned by createMcpModule(), so the tests cover the full
 * stack from HTTP Request objects down through JWT signing/verification.
 */
import { beforeEach, describe, expect, it } from "vitest";
import { createMcpModule } from "../src/mcp/server.js";
import type {
	McpAccessToken,
	McpAuthModule,
	McpAuthorizationCode,
	McpClient,
	McpClientRegistrationResponse,
	McpTokenResponse,
} from "../src/mcp/types.js";
import { computeS256Challenge, generateSecureToken } from "../src/mcp/utils.js";

// ─── Shared constants ─────────────────────────────────────────────────────────

const ISSUER = "https://auth.theauth.test";
const BASE_URL = "https://auth.theauth.test/api/auth";
const SIGNING_SECRET = "test-signing-secret-at-least-32-chars-long!!";
const REDIRECT_URI = "https://app.theauth.test/callback";
const TEST_USER_ID = "user_01HXYZ";

// ─── In-memory store factory ──────────────────────────────────────────────────

interface InMemoryStore {
	clients: Map<string, McpClient>;
	codes: Map<string, McpAuthorizationCode>;
	tokens: Map<string, McpAccessToken>;
	/** tokens indexed by refresh token value */
	tokensByRefresh: Map<string, McpAccessToken>;
}

function createInMemoryStore(): InMemoryStore {
	return {
		clients: new Map(),
		codes: new Map(),
		tokens: new Map(),
		tokensByRefresh: new Map(),
	};
}

function createMcpModuleWithStore(
	store: InMemoryStore,
	resolvedUserId: string | null = TEST_USER_ID,
): McpAuthModule {
	return createMcpModule({
		config: {
			enabled: true,
			issuer: ISSUER,
			baseUrl: BASE_URL,
			signingSecret: SIGNING_SECRET,
			scopes: ["openid", "profile", "email", "offline_access", "mcp:read", "mcp:write"],
			accessTokenTtl: 3600,
			refreshTokenTtl: 604800,
			codeTtl: 600,
		},
		storeClient: async (client) => {
			store.clients.set(client.clientId, client);
		},
		findClient: async (clientId) => store.clients.get(clientId) ?? null,
		storeAuthorizationCode: async (code) => {
			store.codes.set(code.code, code);
		},
		consumeAuthorizationCode: async (code) => {
			const found = store.codes.get(code) ?? null;
			if (found) {
				store.codes.delete(code);
			}
			return found;
		},
		storeToken: async (token) => {
			store.tokens.set(token.accessToken, token);
			if (token.refreshToken) {
				store.tokensByRefresh.set(token.refreshToken, token);
			}
		},
		findTokenByRefreshToken: async (rt) => store.tokensByRefresh.get(rt) ?? null,
		revokeToken: async (accessToken) => {
			const token = store.tokens.get(accessToken);
			if (token) {
				store.tokens.delete(accessToken);
				if (token.refreshToken) {
					store.tokensByRefresh.delete(token.refreshToken);
				}
			}
		},
		resolveUserId: async () => resolvedUserId,
	});
}

// ─── Helper: build an authorize Request ──────────────────────────────────────

function buildAuthorizeRequest(params: Record<string, string>): Request {
	const url = new URL(`${BASE_URL}/mcp/authorize`);
	for (const [k, v] of Object.entries(params)) {
		url.searchParams.set(k, v);
	}
	return new Request(url.toString());
}

// ─── Helper: build a token Request ───────────────────────────────────────────

function buildTokenRequest(body: Record<string, string>): Request {
	return new Request(`${BASE_URL}/mcp/token`, {
		method: "POST",
		headers: { "Content-Type": "application/x-www-form-urlencoded" },
		body: new URLSearchParams(body).toString(),
	});
}

// ─── Helper: generate a valid PKCE pair ──────────────────────────────────────

async function generatePkcePair(): Promise<{ verifier: string; challenge: string }> {
	// code_verifier must be 43-128 chars (URL-safe)
	const verifier = generateSecureToken(43);
	const challenge = await computeS256Challenge(verifier);
	return { verifier, challenge };
}

// ─── Fixture: register a public client and return its registration ────────────

async function registerPublicClient(mcp: McpAuthModule): Promise<McpClientRegistrationResponse> {
	const result = await mcp.registerClient({
		redirect_uris: [REDIRECT_URI],
		token_endpoint_auth_method: "none",
		grant_types: ["authorization_code", "refresh_token"],
		response_types: ["code"],
		client_name: "Test Public Client",
		scope: "openid profile email offline_access",
	});
	if (!result.success) {
		throw new Error(`Client registration failed: ${result.error.message}`);
	}
	return result.data;
}

// ─── Fixture: full auth-code + PKCE exchange returning tokens ────────────────

async function runFullAuthCodeFlow(
	mcp: McpAuthModule,
	clientId: string,
	extraScopes = "openid profile email offline_access",
): Promise<McpTokenResponse> {
	const { verifier, challenge } = await generatePkcePair();

	const authorizeResult = await mcp.authorize(
		buildAuthorizeRequest({
			response_type: "code",
			client_id: clientId,
			redirect_uri: REDIRECT_URI,
			scope: extraScopes,
			state: "test-state",
			code_challenge: challenge,
			code_challenge_method: "S256",
		}),
	);
	if (!authorizeResult.success) {
		throw new Error(`Authorize failed: ${authorizeResult.error.message}`);
	}

	const tokenResult = await mcp.token(
		buildTokenRequest({
			grant_type: "authorization_code",
			code: authorizeResult.data.code,
			redirect_uri: REDIRECT_URI,
			client_id: clientId,
			code_verifier: verifier,
		}),
	);
	if (!tokenResult.success) {
		throw new Error(`Token exchange failed: ${tokenResult.error.message}`);
	}

	return tokenResult.data;
}

// ─── Tests ────────────────────────────────────────────────────────────────────

describe("MCP OAuth 2.1 end-to-end flow", () => {
	let store: InMemoryStore;
	let mcp: McpAuthModule;

	beforeEach(() => {
		store = createInMemoryStore();
		mcp = createMcpModuleWithStore(store);
	});

	// ── 1. Metadata ──────────────────────────────────────────────────────────

	describe("1 · metadata endpoints", () => {
		it("authorization server metadata has all required RFC 8414 fields", () => {
			const meta = mcp.getMetadata();

			expect(meta.issuer).toBe(ISSUER);
			expect(meta.authorization_endpoint).toBe(`${BASE_URL}/mcp/authorize`);
			expect(meta.token_endpoint).toBe(`${BASE_URL}/mcp/token`);
			expect(meta.registration_endpoint).toBe(`${BASE_URL}/mcp/register`);
			expect(meta.jwks_uri).toBeDefined();
			expect(meta.response_types_supported).toContain("code");
			expect(meta.grant_types_supported).toContain("authorization_code");
			expect(meta.grant_types_supported).toContain("refresh_token");
			expect(meta.code_challenge_methods_supported).toEqual(["S256"]);
			expect(meta.token_endpoint_auth_methods_supported).toContain("none");
			expect(meta.token_endpoint_auth_methods_supported).toContain("client_secret_basic");
			expect(meta.scopes_supported).toContain("openid");
			expect(meta.scopes_supported).toContain("mcp:read");
		});

		it("protected resource metadata points at the correct authorization server", () => {
			const meta = mcp.getProtectedResourceMetadata();

			expect(meta.resource).toBe(ISSUER);
			expect(meta.authorization_servers).toContain(ISSUER);
			expect(meta.bearer_methods_supported).toContain("header");
			expect(meta.scopes_supported).toContain("openid");
		});
	});

	// ── 2. Dynamic client registration ───────────────────────────────────────

	describe("2 · dynamic client registration (RFC 7591)", () => {
		it("registers a public client and returns client_id without client_secret", async () => {
			const result = await mcp.registerClient({
				redirect_uris: [REDIRECT_URI],
				token_endpoint_auth_method: "none",
				grant_types: ["authorization_code"],
				response_types: ["code"],
				client_name: "My Public Client",
			});

			expect(result.success).toBe(true);
			if (!result.success) return;

			expect(result.data.client_id).toBeDefined();
			expect(result.data.client_secret).toBeUndefined();
			expect(result.data.token_endpoint_auth_method).toBe("none");
			expect(result.data.redirect_uris).toContain(REDIRECT_URI);
			expect(result.data.grant_types).toContain("authorization_code");
			expect(result.data.client_id_issued_at).toBeGreaterThan(0);

			// Client must be persisted in the store
			const stored = store.clients.get(result.data.client_id);
			expect(stored).toBeDefined();
			expect(stored?.clientType).toBe("public");
		});

		it("registers a confidential client and returns client_secret", async () => {
			const result = await mcp.registerClient({
				redirect_uris: [REDIRECT_URI],
				token_endpoint_auth_method: "client_secret_basic",
				grant_types: ["authorization_code", "refresh_token"],
				response_types: ["code"],
				client_name: "Confidential Service",
			});

			expect(result.success).toBe(true);
			if (!result.success) return;

			expect(result.data.client_id).toBeDefined();
			expect(result.data.client_secret).toBeDefined();
			expect(typeof result.data.client_secret).toBe("string");
			expect((result.data.client_secret ?? "").length).toBeGreaterThan(0);
			expect(result.data.client_secret_expires_at).toBe(0);

			const stored = store.clients.get(result.data.client_id);
			expect(stored?.clientType).toBe("confidential");
		});

		it("rejects registration with no redirect_uris for authorization_code grant", async () => {
			const result = await mcp.registerClient({
				redirect_uris: [],
				token_endpoint_auth_method: "none",
				grant_types: ["authorization_code"],
				response_types: ["code"],
			});

			expect(result.success).toBe(false);
			if (result.success) return;

			expect(result.error.code).toBe("INVALID_REDIRECT_URI");
		});

		it("rejects redirect_uri with a fragment", async () => {
			const result = await mcp.registerClient({
				redirect_uris: [`${REDIRECT_URI}#fragment`],
				token_endpoint_auth_method: "none",
				grant_types: ["authorization_code"],
				response_types: ["code"],
			});

			expect(result.success).toBe(false);
			if (result.success) return;

			expect(result.error.code).toBe("INVALID_REDIRECT_URI");
		});

		it("rejects non-https redirect_uri (not localhost)", async () => {
			const result = await mcp.registerClient({
				redirect_uris: ["http://evil.example.com/callback"],
				token_endpoint_auth_method: "none",
				grant_types: ["authorization_code"],
				response_types: ["code"],
			});

			expect(result.success).toBe(false);
			if (result.success) return;

			expect(result.error.code).toBe("INVALID_REDIRECT_URI");
		});

		it("accepts localhost redirect_uri for development", async () => {
			const result = await mcp.registerClient({
				redirect_uris: ["http://localhost:3000/callback"],
				token_endpoint_auth_method: "none",
				grant_types: ["authorization_code"],
				response_types: ["code"],
			});

			expect(result.success).toBe(true);
		});
	});

	// ── 3. Authorization code flow with PKCE ─────────────────────────────────

	describe("3 · authorization code flow with PKCE", () => {
		it("issues an authorization code for a valid request", async () => {
			const reg = await registerPublicClient(mcp);
			const { challenge } = await generatePkcePair();

			const result = await mcp.authorize(
				buildAuthorizeRequest({
					response_type: "code",
					client_id: reg.client_id,
					redirect_uri: REDIRECT_URI,
					scope: "openid profile",
					state: "abc123",
					code_challenge: challenge,
					code_challenge_method: "S256",
				}),
			);

			expect(result.success).toBe(true);
			if (!result.success) return;

			expect(result.data.code).toBeDefined();
			expect(result.data.state).toBe("abc123");
			expect(result.data.redirectUri).toContain(REDIRECT_URI);
			expect(result.data.redirectUri).toContain(`code=${result.data.code}`);
			expect(result.data.redirectUri).toContain("state=abc123");

			// Code must be stored
			const stored = store.codes.get(result.data.code);
			expect(stored).toBeDefined();
			expect(stored?.userId).toBe(TEST_USER_ID);
			expect(stored?.clientId).toBe(reg.client_id);
		});

		it("exchanges authorization code for access_token and refresh_token", async () => {
			const reg = await registerPublicClient(mcp);
			const { verifier, challenge } = await generatePkcePair();

			const authorizeResult = await mcp.authorize(
				buildAuthorizeRequest({
					response_type: "code",
					client_id: reg.client_id,
					redirect_uri: REDIRECT_URI,
					scope: "openid profile email offline_access",
					code_challenge: challenge,
					code_challenge_method: "S256",
				}),
			);
			expect(authorizeResult.success).toBe(true);
			if (!authorizeResult.success) return;

			const tokenResult = await mcp.token(
				buildTokenRequest({
					grant_type: "authorization_code",
					code: authorizeResult.data.code,
					redirect_uri: REDIRECT_URI,
					client_id: reg.client_id,
					code_verifier: verifier,
				}),
			);

			expect(tokenResult.success).toBe(true);
			if (!tokenResult.success) return;

			expect(tokenResult.data.access_token).toBeDefined();
			expect(tokenResult.data.token_type).toBe("Bearer");
			expect(tokenResult.data.expires_in).toBe(3600);
			expect(tokenResult.data.refresh_token).toBeDefined();
			expect(tokenResult.data.scope).toContain("openid");

			// access_token must be a 3-part JWT
			const parts = tokenResult.data.access_token.split(".");
			expect(parts).toHaveLength(3);
		});

		it("does NOT return refresh_token when offline_access scope is absent", async () => {
			const reg = await registerPublicClient(mcp);
			const tokens = await runFullAuthCodeFlow(mcp, reg.client_id, "openid profile");

			// No offline_access → no refresh token
			expect(tokens.refresh_token).toBeUndefined();
		});

		it("consumes the authorization code (one-time use)", async () => {
			const reg = await registerPublicClient(mcp);
			const { verifier, challenge } = await generatePkcePair();

			const authorizeResult = await mcp.authorize(
				buildAuthorizeRequest({
					response_type: "code",
					client_id: reg.client_id,
					redirect_uri: REDIRECT_URI,
					scope: "openid offline_access",
					code_challenge: challenge,
					code_challenge_method: "S256",
				}),
			);
			expect(authorizeResult.success).toBe(true);
			if (!authorizeResult.success) return;

			const code = authorizeResult.data.code;

			// First exchange succeeds
			const first = await mcp.token(
				buildTokenRequest({
					grant_type: "authorization_code",
					code,
					redirect_uri: REDIRECT_URI,
					client_id: reg.client_id,
					code_verifier: verifier,
				}),
			);
			expect(first.success).toBe(true);

			// Second exchange with the same code must fail (code was consumed)
			const second = await mcp.token(
				buildTokenRequest({
					grant_type: "authorization_code",
					code,
					redirect_uri: REDIRECT_URI,
					client_id: reg.client_id,
					code_verifier: verifier,
				}),
			);
			expect(second.success).toBe(false);
			if (second.success) return;
			expect(second.error.code).toBe("INVALID_GRANT");
		});
	});

	// ── 4. Token validation ───────────────────────────────────────────────────

	describe("4 · token validation", () => {
		it("validates a freshly issued access token", async () => {
			const reg = await registerPublicClient(mcp);
			const tokens = await runFullAuthCodeFlow(mcp, reg.client_id);

			const result = await mcp.validateToken(tokens.access_token);

			expect(result.success).toBe(true);
			if (!result.success) return;

			expect(result.data.userId).toBe(TEST_USER_ID);
			expect(result.data.clientId).toBe(reg.client_id);
			expect(result.data.scopes).toContain("openid");
			expect(result.data.expiresAt.getTime()).toBeGreaterThan(Date.now());
			expect(result.data.tokenId).toBeDefined();
		});

		it("validates required scopes successfully", async () => {
			const reg = await registerPublicClient(mcp);
			const tokens = await runFullAuthCodeFlow(
				mcp,
				reg.client_id,
				"openid profile email offline_access mcp:read",
			);

			const result = await mcp.validateToken(tokens.access_token, ["openid", "mcp:read"]);
			expect(result.success).toBe(true);
		});

		it("fails when required scope is missing from the token", async () => {
			const reg = await registerPublicClient(mcp);
			const tokens = await runFullAuthCodeFlow(mcp, reg.client_id, "openid profile");

			const result = await mcp.validateToken(tokens.access_token, ["mcp:write"]);

			expect(result.success).toBe(false);
			if (result.success) return;
			expect(result.error.code).toBe("INSUFFICIENT_SCOPE");
		});

		it("rejects a completely invalid (garbage) token", async () => {
			const result = await mcp.validateToken("not.a.valid.jwt");

			expect(result.success).toBe(false);
			if (result.success) return;
			expect(result.error.code).toBe("INVALID_TOKEN");
		});

		it("rejects an expired token", async () => {
			// Create a module with 0-second token TTL so it expires instantly
			const shortStore = createInMemoryStore();
			const shortMcp = createMcpModule({
				config: {
					enabled: true,
					issuer: ISSUER,
					baseUrl: BASE_URL,
					signingSecret: SIGNING_SECRET,
					accessTokenTtl: 0, // expires immediately
					refreshTokenTtl: 604800,
					codeTtl: 600,
				},
				storeClient: async (c) => {
					shortStore.clients.set(c.clientId, c);
				},
				findClient: async (id) => shortStore.clients.get(id) ?? null,
				storeAuthorizationCode: async (c) => {
					shortStore.codes.set(c.code, c);
				},
				consumeAuthorizationCode: async (code) => {
					const found = shortStore.codes.get(code) ?? null;
					if (found) shortStore.codes.delete(code);
					return found;
				},
				storeToken: async (t) => {
					shortStore.tokens.set(t.accessToken, t);
					if (t.refreshToken) shortStore.tokensByRefresh.set(t.refreshToken, t);
				},
				findTokenByRefreshToken: async (rt) => shortStore.tokensByRefresh.get(rt) ?? null,
				revokeToken: async (at) => {
					const t = shortStore.tokens.get(at);
					if (t) {
						shortStore.tokens.delete(at);
						if (t.refreshToken) shortStore.tokensByRefresh.delete(t.refreshToken);
					}
				},
				resolveUserId: async () => TEST_USER_ID,
			});

			const regResult = await shortMcp.registerClient({
				redirect_uris: [REDIRECT_URI],
				token_endpoint_auth_method: "none",
				grant_types: ["authorization_code"],
				response_types: ["code"],
			});
			expect(regResult.success).toBe(true);
			if (!regResult.success) return;

			const { verifier, challenge } = await generatePkcePair();
			const authResult = await shortMcp.authorize(
				buildAuthorizeRequest({
					response_type: "code",
					client_id: regResult.data.client_id,
					redirect_uri: REDIRECT_URI,
					scope: "openid",
					code_challenge: challenge,
					code_challenge_method: "S256",
				}),
			);
			expect(authResult.success).toBe(true);
			if (!authResult.success) return;

			const tokenResult = await shortMcp.token(
				buildTokenRequest({
					grant_type: "authorization_code",
					code: authResult.data.code,
					redirect_uri: REDIRECT_URI,
					client_id: regResult.data.client_id,
					code_verifier: verifier,
				}),
			);
			expect(tokenResult.success).toBe(true);
			if (!tokenResult.success) return;

			// Wait a tick to ensure the 0-second TTL has elapsed
			await new Promise<void>((resolve) => setTimeout(resolve, 10));

			const validation = await shortMcp.validateToken(tokenResult.data.access_token);
			expect(validation.success).toBe(false);
			if (validation.success) return;
			expect(["TOKEN_EXPIRED", "INVALID_TOKEN"]).toContain(validation.error.code);
		});
	});

	// ── 5. Refresh token flow ─────────────────────────────────────────────────

	describe("5 · refresh token flow", () => {
		it("exchanges a refresh_token for a new access_token", async () => {
			const reg = await registerPublicClient(mcp);
			const first = await runFullAuthCodeFlow(mcp, reg.client_id);

			expect(first.refresh_token).toBeDefined();
			const oldRefreshToken = first.refresh_token as string;
			const oldAccessToken = first.access_token;

			const refreshResult = await mcp.token(
				buildTokenRequest({
					grant_type: "refresh_token",
					refresh_token: oldRefreshToken,
					client_id: reg.client_id,
				}),
			);

			expect(refreshResult.success).toBe(true);
			if (!refreshResult.success) return;

			expect(refreshResult.data.access_token).toBeDefined();
			expect(refreshResult.data.access_token).not.toBe(oldAccessToken);
			expect(refreshResult.data.refresh_token).toBeDefined();
			expect(refreshResult.data.refresh_token).not.toBe(oldRefreshToken);
			expect(refreshResult.data.token_type).toBe("Bearer");
		});

		it("rotates the refresh token (old refresh_token is invalidated)", async () => {
			const reg = await registerPublicClient(mcp);
			const first = await runFullAuthCodeFlow(mcp, reg.client_id);
			const oldRefreshToken = first.refresh_token as string;

			// First refresh succeeds
			const firstRefresh = await mcp.token(
				buildTokenRequest({
					grant_type: "refresh_token",
					refresh_token: oldRefreshToken,
					client_id: reg.client_id,
				}),
			);
			expect(firstRefresh.success).toBe(true);

			// Second use of old refresh_token must fail
			const secondRefresh = await mcp.token(
				buildTokenRequest({
					grant_type: "refresh_token",
					refresh_token: oldRefreshToken,
					client_id: reg.client_id,
				}),
			);
			expect(secondRefresh.success).toBe(false);
			if (secondRefresh.success) return;
			expect(secondRefresh.error.code).toBe("INVALID_GRANT");
		});

		it("new access token from refresh is valid and has correct claims", async () => {
			const reg = await registerPublicClient(mcp);
			const first = await runFullAuthCodeFlow(mcp, reg.client_id);

			const refreshResult = await mcp.token(
				buildTokenRequest({
					grant_type: "refresh_token",
					refresh_token: first.refresh_token as string,
					client_id: reg.client_id,
				}),
			);
			expect(refreshResult.success).toBe(true);
			if (!refreshResult.success) return;

			const validation = await mcp.validateToken(refreshResult.data.access_token);
			expect(validation.success).toBe(true);
			if (!validation.success) return;
			expect(validation.data.userId).toBe(TEST_USER_ID);
			expect(validation.data.clientId).toBe(reg.client_id);
		});

		it("rejects an invalid refresh_token", async () => {
			const reg = await registerPublicClient(mcp);

			const result = await mcp.token(
				buildTokenRequest({
					grant_type: "refresh_token",
					refresh_token: "totally-fake-refresh-token",
					client_id: reg.client_id,
				}),
			);

			expect(result.success).toBe(false);
			if (result.success) return;
			expect(result.error.code).toBe("INVALID_GRANT");
		});
	});

	// ── 6. withMcpAuth middleware ─────────────────────────────────────────────

	describe("6 · withMcpAuth middleware", () => {
		it("returns a valid session for a request bearing a valid token", async () => {
			const reg = await registerPublicClient(mcp);
			const tokens = await runFullAuthCodeFlow(mcp, reg.client_id);

			const request = new Request("https://mcp.theauth.test/tools", {
				headers: { Authorization: `Bearer ${tokens.access_token}` },
			});

			const result = await mcp.middleware(request);

			expect(result.success).toBe(true);
			if (!result.success) return;
			expect(result.data.userId).toBe(TEST_USER_ID);
			expect(result.data.clientId).toBe(reg.client_id);
		});

		it("returns UNAUTHORIZED when no Authorization header is present", async () => {
			const request = new Request("https://mcp.theauth.test/tools");

			const result = await mcp.middleware(request);

			expect(result.success).toBe(false);
			if (result.success) return;
			expect(result.error.code).toBe("UNAUTHORIZED");
		});

		it("returns error for a malformed Bearer token", async () => {
			const request = new Request("https://mcp.theauth.test/tools", {
				headers: { Authorization: "Bearer this-is-not-a-jwt" },
			});

			const result = await mcp.middleware(request);

			expect(result.success).toBe(false);
			if (result.success) return;
			// Should be INVALID_TOKEN (not 500)
			expect(["INVALID_TOKEN", "TOKEN_EXPIRED", "INVALID_AUDIENCE"]).toContain(result.error.code);
		});

		it("returns error for a token signed with a different secret", async () => {
			// Sign a token with a different module (different secret)
			const altStore = createInMemoryStore();
			const altMcp = createMcpModule({
				config: {
					enabled: true,
					issuer: ISSUER,
					baseUrl: BASE_URL,
					signingSecret: "a-completely-different-secret-that-is-long-enough!!",
					accessTokenTtl: 3600,
					refreshTokenTtl: 604800,
					codeTtl: 600,
				},
				storeClient: async (c) => {
					altStore.clients.set(c.clientId, c);
				},
				findClient: async (id) => altStore.clients.get(id) ?? null,
				storeAuthorizationCode: async (c) => {
					altStore.codes.set(c.code, c);
				},
				consumeAuthorizationCode: async (code) => {
					const found = altStore.codes.get(code) ?? null;
					if (found) altStore.codes.delete(code);
					return found;
				},
				storeToken: async (t) => {
					altStore.tokens.set(t.accessToken, t);
					if (t.refreshToken) altStore.tokensByRefresh.set(t.refreshToken, t);
				},
				findTokenByRefreshToken: async (rt) => altStore.tokensByRefresh.get(rt) ?? null,
				revokeToken: async (at) => {
					const t = altStore.tokens.get(at);
					if (t) {
						altStore.tokens.delete(at);
						if (t.refreshToken) altStore.tokensByRefresh.delete(t.refreshToken);
					}
				},
				resolveUserId: async () => TEST_USER_ID,
			});

			const altReg = await altMcp.registerClient({
				redirect_uris: [REDIRECT_URI],
				token_endpoint_auth_method: "none",
				grant_types: ["authorization_code"],
				response_types: ["code"],
			});
			expect(altReg.success).toBe(true);
			if (!altReg.success) return;

			const altTokens = await runFullAuthCodeFlow(altMcp, altReg.data.client_id, "openid");

			// Validate the alt token against the ORIGINAL module (different secret)
			const result = await mcp.middleware(
				new Request("https://mcp.theauth.test/tools", {
					headers: { Authorization: `Bearer ${altTokens.access_token}` },
				}),
			);

			expect(result.success).toBe(false);
		});
	});

	// ── 7. Authorization error cases ─────────────────────────────────────────

	describe("7 · authorization error cases", () => {
		it("rejects authorize with unknown client_id", async () => {
			const { challenge } = await generatePkcePair();

			const result = await mcp.authorize(
				buildAuthorizeRequest({
					response_type: "code",
					client_id: "nonexistent-client-id",
					redirect_uri: REDIRECT_URI,
					scope: "openid",
					code_challenge: challenge,
					code_challenge_method: "S256",
				}),
			);

			expect(result.success).toBe(false);
			if (result.success) return;
			expect(result.error.code).toBe("INVALID_CLIENT");
		});

		it("rejects authorize with mismatched redirect_uri", async () => {
			const reg = await registerPublicClient(mcp);
			const { challenge } = await generatePkcePair();

			const result = await mcp.authorize(
				buildAuthorizeRequest({
					response_type: "code",
					client_id: reg.client_id,
					redirect_uri: "https://evil.example.com/hijack",
					scope: "openid",
					code_challenge: challenge,
					code_challenge_method: "S256",
				}),
			);

			expect(result.success).toBe(false);
			if (result.success) return;
			expect(result.error.code).toBe("INVALID_REDIRECT_URI");
		});

		it("rejects authorize when PKCE challenge is missing (schema-level)", async () => {
			const reg = await registerPublicClient(mcp);

			// code_challenge is missing → schema should reject
			const result = await mcp.authorize(
				buildAuthorizeRequest({
					response_type: "code",
					client_id: reg.client_id,
					redirect_uri: REDIRECT_URI,
					scope: "openid",
					// no code_challenge or code_challenge_method
				}),
			);

			expect(result.success).toBe(false);
			if (result.success) return;
			expect(result.error.code).toBe("INVALID_REQUEST");
		});

		it("rejects authorize when unauthenticated (resolveUserId returns null)", async () => {
			// Build a module where no user is authenticated
			const unauthStore = createInMemoryStore();
			const unauthMcp = createMcpModuleWithStore(unauthStore, null);

			const regResult = await unauthMcp.registerClient({
				redirect_uris: [REDIRECT_URI],
				token_endpoint_auth_method: "none",
				grant_types: ["authorization_code"],
				response_types: ["code"],
			});
			expect(regResult.success).toBe(true);
			if (!regResult.success) return;

			const { challenge } = await generatePkcePair();

			const result = await unauthMcp.authorize(
				buildAuthorizeRequest({
					response_type: "code",
					client_id: regResult.data.client_id,
					redirect_uri: REDIRECT_URI,
					scope: "openid",
					code_challenge: challenge,
					code_challenge_method: "S256",
				}),
			);

			expect(result.success).toBe(false);
			if (result.success) return;
			expect(result.error.code).toBe("LOGIN_REQUIRED");
		});

		it("rejects authorize with an unsupported scope", async () => {
			const reg = await registerPublicClient(mcp);
			const { challenge } = await generatePkcePair();

			const result = await mcp.authorize(
				buildAuthorizeRequest({
					response_type: "code",
					client_id: reg.client_id,
					redirect_uri: REDIRECT_URI,
					scope: "openid unknown:scope:xyz",
					code_challenge: challenge,
					code_challenge_method: "S256",
				}),
			);

			expect(result.success).toBe(false);
			if (result.success) return;
			expect(result.error.code).toBe("INVALID_SCOPE");
		});
	});

	// ── 8. Token-exchange error cases ─────────────────────────────────────────

	describe("8 · token-exchange error cases", () => {
		it("rejects token exchange with wrong code_verifier", async () => {
			const reg = await registerPublicClient(mcp);
			const { challenge } = await generatePkcePair();

			const authResult = await mcp.authorize(
				buildAuthorizeRequest({
					response_type: "code",
					client_id: reg.client_id,
					redirect_uri: REDIRECT_URI,
					scope: "openid",
					code_challenge: challenge,
					code_challenge_method: "S256",
				}),
			);
			expect(authResult.success).toBe(true);
			if (!authResult.success) return;

			// Deliberately wrong verifier (same length to pass schema, wrong value)
			const wrongVerifier = generateSecureToken(43);

			const tokenResult = await mcp.token(
				buildTokenRequest({
					grant_type: "authorization_code",
					code: authResult.data.code,
					redirect_uri: REDIRECT_URI,
					client_id: reg.client_id,
					code_verifier: wrongVerifier,
				}),
			);

			expect(tokenResult.success).toBe(false);
			if (tokenResult.success) return;
			expect(tokenResult.error.code).toBe("INVALID_GRANT");
		});

		it("rejects token exchange with mismatched redirect_uri", async () => {
			const reg = await registerPublicClient(mcp);
			const { verifier, challenge } = await generatePkcePair();

			const authResult = await mcp.authorize(
				buildAuthorizeRequest({
					response_type: "code",
					client_id: reg.client_id,
					redirect_uri: REDIRECT_URI,
					scope: "openid",
					code_challenge: challenge,
					code_challenge_method: "S256",
				}),
			);
			expect(authResult.success).toBe(true);
			if (!authResult.success) return;

			const tokenResult = await mcp.token(
				buildTokenRequest({
					grant_type: "authorization_code",
					code: authResult.data.code,
					redirect_uri: "https://different.example.com/callback",
					client_id: reg.client_id,
					code_verifier: verifier,
				}),
			);

			expect(tokenResult.success).toBe(false);
			if (tokenResult.success) return;
			expect(tokenResult.error.code).toBe("INVALID_GRANT");
		});

		it("rejects token exchange when client_id is absent", async () => {
			const result = await mcp.token(
				buildTokenRequest({
					grant_type: "authorization_code",
					code: "any-code",
					redirect_uri: REDIRECT_URI,
					// client_id omitted
					code_verifier: generateSecureToken(43),
				}),
			);

			expect(result.success).toBe(false);
			if (result.success) return;
			expect(result.error.code).toBe("INVALID_CLIENT");
		});

		it("rejects token exchange for an expired authorization code", async () => {
			// Build a module with 0-second code TTL so the code expires immediately
			const shortCodeStore = createInMemoryStore();
			const shortCodeMcp = createMcpModule({
				config: {
					enabled: true,
					issuer: ISSUER,
					baseUrl: BASE_URL,
					signingSecret: SIGNING_SECRET,
					accessTokenTtl: 3600,
					refreshTokenTtl: 604800,
					codeTtl: 0, // expires instantly
				},
				storeClient: async (c) => {
					shortCodeStore.clients.set(c.clientId, c);
				},
				findClient: async (id) => shortCodeStore.clients.get(id) ?? null,
				storeAuthorizationCode: async (c) => {
					shortCodeStore.codes.set(c.code, c);
				},
				consumeAuthorizationCode: async (code) => {
					const found = shortCodeStore.codes.get(code) ?? null;
					if (found) shortCodeStore.codes.delete(code);
					return found;
				},
				storeToken: async (t) => {
					shortCodeStore.tokens.set(t.accessToken, t);
					if (t.refreshToken) shortCodeStore.tokensByRefresh.set(t.refreshToken, t);
				},
				findTokenByRefreshToken: async (rt) => shortCodeStore.tokensByRefresh.get(rt) ?? null,
				revokeToken: async (at) => {
					const t = shortCodeStore.tokens.get(at);
					if (t) {
						shortCodeStore.tokens.delete(at);
						if (t.refreshToken) shortCodeStore.tokensByRefresh.delete(t.refreshToken);
					}
				},
				resolveUserId: async () => TEST_USER_ID,
			});

			const regResult = await shortCodeMcp.registerClient({
				redirect_uris: [REDIRECT_URI],
				token_endpoint_auth_method: "none",
				grant_types: ["authorization_code"],
				response_types: ["code"],
			});
			expect(regResult.success).toBe(true);
			if (!regResult.success) return;

			const { verifier, challenge } = await generatePkcePair();

			const authResult = await shortCodeMcp.authorize(
				buildAuthorizeRequest({
					response_type: "code",
					client_id: regResult.data.client_id,
					redirect_uri: REDIRECT_URI,
					scope: "openid",
					code_challenge: challenge,
					code_challenge_method: "S256",
				}),
			);
			expect(authResult.success).toBe(true);
			if (!authResult.success) return;

			// Wait for the 0-second TTL to elapse
			await new Promise<void>((resolve) => setTimeout(resolve, 10));

			const tokenResult = await shortCodeMcp.token(
				buildTokenRequest({
					grant_type: "authorization_code",
					code: authResult.data.code,
					redirect_uri: REDIRECT_URI,
					client_id: regResult.data.client_id,
					code_verifier: verifier,
				}),
			);

			expect(tokenResult.success).toBe(false);
			if (tokenResult.success) return;
			expect(tokenResult.error.code).toBe("INVALID_GRANT");
		});

		it("rejects confidential client with wrong secret", async () => {
			const confResult = await mcp.registerClient({
				redirect_uris: [REDIRECT_URI],
				token_endpoint_auth_method: "client_secret_basic",
				grant_types: ["authorization_code"],
				response_types: ["code"],
				client_name: "Confidential Client",
			});
			expect(confResult.success).toBe(true);
			if (!confResult.success) return;

			const { verifier, challenge } = await generatePkcePair();

			const authResult = await mcp.authorize(
				buildAuthorizeRequest({
					response_type: "code",
					client_id: confResult.data.client_id,
					redirect_uri: REDIRECT_URI,
					scope: "openid",
					code_challenge: challenge,
					code_challenge_method: "S256",
				}),
			);
			expect(authResult.success).toBe(true);
			if (!authResult.success) return;

			// Provide a wrong client_secret via body
			const tokenResult = await mcp.token(
				buildTokenRequest({
					grant_type: "authorization_code",
					code: authResult.data.code,
					redirect_uri: REDIRECT_URI,
					client_id: confResult.data.client_id,
					client_secret: "wrong-secret-value",
					code_verifier: verifier,
				}),
			);

			expect(tokenResult.success).toBe(false);
			if (tokenResult.success) return;
			expect(tokenResult.error.code).toBe("INVALID_CLIENT");
		});
	});

	// ── 9. createMcpModule config validation ─────────────────────────────────

	describe("9 · createMcpModule config validation", () => {
		it("throws when issuer is missing", () => {
			expect(() =>
				createMcpModule({
					config: {
						enabled: true,
						baseUrl: BASE_URL,
						signingSecret: SIGNING_SECRET,
					},
					storeClient: async () => {},
					findClient: async () => null,
					storeAuthorizationCode: async () => {},
					consumeAuthorizationCode: async () => null,
					storeToken: async () => {},
					findTokenByRefreshToken: async () => null,
					revokeToken: async () => {},
					resolveUserId: async () => null,
				}),
			).toThrow("issuer");
		});

		it("throws when signingSecret is too short", () => {
			expect(() =>
				createMcpModule({
					config: {
						enabled: true,
						issuer: ISSUER,
						baseUrl: BASE_URL,
						signingSecret: "short",
					},
					storeClient: async () => {},
					findClient: async () => null,
					storeAuthorizationCode: async () => {},
					consumeAuthorizationCode: async () => null,
					storeToken: async () => {},
					findTokenByRefreshToken: async () => null,
					revokeToken: async () => {},
					resolveUserId: async () => null,
				}),
			).toThrow("32");
		});
	});
});
