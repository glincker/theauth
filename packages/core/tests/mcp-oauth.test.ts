import { describe, expect, it } from "vitest";
import {
	getAuthorizationServerMetadata,
	getProtectedResourceMetadata,
} from "../src/mcp/metadata.js";
import {
	McpAuthorizeRequestSchema,
	McpClientRegistrationSchema,
	McpTokenRequestSchema,
} from "../src/mcp/types.js";
import {
	computeS256Challenge,
	extractBasicAuth,
	extractBearerToken,
	generateSecureToken,
	verifyS256,
} from "../src/mcp/utils.js";

describe("MCP OAuth 2.1", () => {
	describe("utils", () => {
		it("generates secure tokens", () => {
			const token1 = generateSecureToken(32);
			const token2 = generateSecureToken(32);
			expect(token1).not.toBe(token2);
			expect(token1.length).toBeGreaterThan(30);
		});

		it("computes S256 challenge", async () => {
			const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
			const challenge = await computeS256Challenge(verifier);
			expect(challenge).toBeDefined();
			expect(challenge.length).toBeGreaterThan(0);
		});

		it("verifies S256 correctly", async () => {
			const verifier = generateSecureToken(43);
			const challenge = await computeS256Challenge(verifier);

			const valid = await verifyS256(verifier, challenge);
			expect(valid).toBe(true);

			const invalid = await verifyS256(
				"wrong-verifier-value-that-is-long-enough-43chars",
				challenge,
			);
			expect(invalid).toBe(false);
		});

		it("extracts Basic auth", () => {
			const encoded = Buffer.from("client123:secret456").toString("base64");
			const req = new Request("http://localhost", {
				headers: { Authorization: `Basic ${encoded}` },
			});
			const result = extractBasicAuth(req);
			expect(result).not.toBeNull();
			expect(result?.[0]).toBe("client123");
			expect(result?.[1]).toBe("secret456");
		});

		it("returns null for invalid Basic auth", () => {
			const req1 = new Request("http://localhost", {
				headers: { Authorization: "Bearer token123" },
			});
			expect(extractBasicAuth(req1)).toBeNull();

			const req2 = new Request("http://localhost");
			expect(extractBasicAuth(req2)).toBeNull();
		});

		it("extracts Bearer token", () => {
			const req1 = new Request("http://localhost", {
				headers: { Authorization: "Bearer eyJhbGc" },
			});
			expect(extractBearerToken(req1)).toBe("eyJhbGc");

			const req2 = new Request("http://localhost", {
				headers: { Authorization: "Basic abc" },
			});
			expect(extractBearerToken(req2)).toBeNull();

			const req3 = new Request("http://localhost");
			expect(extractBearerToken(req3)).toBeNull();
		});
	});

	describe("metadata", () => {
		const ctx = {
			config: {
				enabled: true,
				issuer: "https://auth.example.com",
				baseUrl: "https://auth.example.com/api/auth",
				scopes: ["openid", "profile", "agent:read", "agent:write"],
				accessTokenTtl: 3600,
				refreshTokenTtl: 604800,
				codeTtl: 600,
			},
			storeClient: async () => {},
			findClient: async () => null,
			storeAuthorizationCode: async () => {},
			consumeAuthorizationCode: async () => null,
			storeToken: async () => {},
			findTokenByRefreshToken: async () => null,
			revokeToken: async () => {},
			resolveUserId: async () => null,
		} as Parameters<typeof getAuthorizationServerMetadata>[0];

		it("generates authorization server metadata (RFC 8414)", () => {
			const metadata = getAuthorizationServerMetadata(ctx);

			expect(metadata.issuer).toBe("https://auth.example.com");
			expect(metadata.authorization_endpoint).toBe(
				"https://auth.example.com/api/auth/mcp/authorize",
			);
			expect(metadata.token_endpoint).toBe("https://auth.example.com/api/auth/mcp/token");
			expect(metadata.registration_endpoint).toBe("https://auth.example.com/api/auth/mcp/register");
			expect(metadata.code_challenge_methods_supported).toEqual(["S256"]);
			expect(metadata.grant_types_supported).toContain("authorization_code");
			expect(metadata.grant_types_supported).toContain("refresh_token");
			expect(metadata.response_types_supported).toEqual(["code"]);
			expect(metadata.scopes_supported).toContain("openid");
			expect(metadata.scopes_supported).toContain("agent:read");
		});

		it("generates protected resource metadata (RFC 9728)", () => {
			const metadata = getProtectedResourceMetadata(ctx);

			expect(metadata.resource).toBe("https://auth.example.com");
			expect(metadata.authorization_servers).toContain("https://auth.example.com");
			expect(metadata.bearer_methods_supported).toEqual(["header"]);
			expect(metadata.scopes_supported).toContain("openid");
		});
	});

	describe("zod schemas", () => {
		it("validates client registration request", () => {
			const valid = McpClientRegistrationSchema.safeParse({
				redirect_uris: ["https://example.com/callback"],
				client_name: "My MCP Client",
				grant_types: ["authorization_code"],
				response_types: ["code"],
				token_endpoint_auth_method: "none",
			});
			expect(valid.success).toBe(true);
		});

		it("rejects invalid client registration", () => {
			const invalid = McpClientRegistrationSchema.safeParse({
				redirect_uris: ["not-a-url"],
			});
			expect(invalid.success).toBe(false);
		});

		it("validates authorize request", () => {
			const valid = McpAuthorizeRequestSchema.safeParse({
				response_type: "code",
				client_id: "client-123",
				redirect_uri: "https://example.com/callback",
				code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM-long-enough",
				code_challenge_method: "S256",
				scope: "openid profile",
				state: "random-state",
				resource: "https://mcp.example.com",
			});
			expect(valid.success).toBe(true);
		});

		it("rejects plain PKCE method", () => {
			const result = McpAuthorizeRequestSchema.safeParse({
				response_type: "code",
				client_id: "client-123",
				redirect_uri: "https://example.com/callback",
				code_challenge: "some-challenge-value-that-is-long-enough-43chars",
				code_challenge_method: "plain", // MUST be rejected
			});
			expect(result.success).toBe(false);
		});

		it("validates token request (authorization_code)", () => {
			const valid = McpTokenRequestSchema.safeParse({
				grant_type: "authorization_code",
				code: "auth-code-123",
				redirect_uri: "https://example.com/callback",
				client_id: "client-123",
				code_verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk-more",
				resource: "https://mcp.example.com",
			});
			expect(valid.success).toBe(true);
		});

		it("validates token request (refresh_token)", () => {
			const valid = McpTokenRequestSchema.safeParse({
				grant_type: "refresh_token",
				refresh_token: "refresh-token-123",
				client_id: "client-123",
			});
			expect(valid.success).toBe(true);
		});

		it("rejects unknown grant types", () => {
			const result = McpTokenRequestSchema.safeParse({
				grant_type: "password",
				client_id: "client-123",
			});
			expect(result.success).toBe(false);
		});

		it("parses client_credentials (the grant itself is opt in at the endpoint)", () => {
			const result = McpTokenRequestSchema.safeParse({
				grant_type: "client_credentials",
				client_id: "client-123",
			});
			expect(result.success).toBe(true);
		});
	});
});
