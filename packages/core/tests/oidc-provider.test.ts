/**
 * Tests for the OIDC Provider module.
 *
 * Covers:
 * - Client registration, retrieval, and deletion
 * - Authorization code flow (with and without PKCE)
 * - Token exchange (authorization_code grant)
 * - Token refresh (refresh_token grant)
 * - Refresh token rotation
 * - ID token claims (sub, iss, aud, nonce, at_hash)
 * - UserInfo endpoint
 * - Discovery document
 * - JWKS
 * - Access token validation (valid, expired, malformed)
 * - Error cases: invalid client, expired code, code reuse, bad redirect_uri,
 *   bad PKCE, client mismatch, missing client secret
 */

import { createHash } from "node:crypto";
import * as jose from "jose";
import { beforeEach, describe, expect, it } from "vitest";
import type { OidcProviderModule, UserInfoClaims } from "../src/auth/oidc-provider.js";
import { createOidcProviderModule } from "../src/auth/oidc-provider.js";
import type { Database } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function createTestDb(): Promise<Database> {
	const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite");
	return db;
}

/** Generate a fresh RSA key pair for each test suite. Keys must be extractable for JWK export. */
async function createTestKeyPair(): Promise<{ privateKey: CryptoKey; publicKey: CryptoKey }> {
	const pair = await jose.generateKeyPair("RS256", { extractable: true });
	return { privateKey: pair.privateKey as CryptoKey, publicKey: pair.publicKey as CryptoKey };
}

const TEST_ISSUER = "https://auth.test.com";

/** Stub getUserClaims that returns predictable data. */
async function stubGetUserClaims(userId: string, scopes: string[]): Promise<UserInfoClaims> {
	const claims: UserInfoClaims = { sub: userId };
	if (scopes.includes("email")) {
		claims.email = `${userId}@example.com`;
		claims.emailVerified = true;
	}
	if (scopes.includes("profile")) {
		claims.name = `User ${userId}`;
		claims.picture = `https://example.com/avatar/${userId}.png`;
	}
	return claims;
}

/** Generate a PKCE code verifier + challenge pair. */
async function generatePkce(): Promise<{ codeVerifier: string; codeChallenge: string }> {
	const verifierBytes = new Uint8Array(32);
	globalThis.crypto.getRandomValues(verifierBytes);
	const codeVerifier = jose.base64url.encode(verifierBytes);

	const encoder = new TextEncoder();
	const digest = await globalThis.crypto.subtle.digest("SHA-256", encoder.encode(codeVerifier));
	const codeChallenge = jose.base64url.encode(new Uint8Array(digest));

	return { codeVerifier, codeChallenge };
}

/** Register a client and return the full result data (clientId + clientSecret). */
async function registerTestClient(mod: OidcProviderModule) {
	const result = await mod.registerClient({
		clientName: "Test App",
		redirectUris: ["https://app.example.com/callback"],
	});
	expect(result.success).toBe(true);
	if (!result.success) throw new Error("registerClient failed");
	return result.data;
}

/** Run the full authorize -> exchangeToken flow. */
async function runAuthCodeFlow(
	mod: OidcProviderModule,
	opts: {
		clientId: string;
		clientSecret: string | null;
		userId?: string;
		scopes?: string;
		nonce?: string;
		pkce?: { codeVerifier: string; codeChallenge: string };
	},
) {
	const userId = opts.userId ?? "user-1";
	const scopes = opts.scopes ?? "openid email profile";

	const authorizeResult = await mod.authorize({
		clientId: opts.clientId,
		redirectUri: "https://app.example.com/callback",
		responseType: "code",
		scope: scopes,
		state: "test-state",
		nonce: opts.nonce,
		codeChallenge: opts.pkce?.codeChallenge,
		codeChallengeMethod: opts.pkce ? "S256" : undefined,
		userId,
	});
	expect(authorizeResult.success).toBe(true);
	if (!authorizeResult.success) throw new Error("authorize failed");

	const tokenResult = await mod.exchangeToken({
		grantType: "authorization_code",
		code: authorizeResult.data.code,
		redirectUri: "https://app.example.com/callback",
		codeVerifier: opts.pkce?.codeVerifier,
		clientId: opts.clientId,
		clientSecret: opts.clientSecret ?? undefined,
	});

	return { authorizeResult, tokenResult };
}

// ---------------------------------------------------------------------------
// Client registration
// ---------------------------------------------------------------------------

describe("OidcProvider.registerClient", () => {
	let db: Database;
	let mod: OidcProviderModule;

	beforeEach(async () => {
		db = await createTestDb();
		const { privateKey } = await createTestKeyPair();
		mod = createOidcProviderModule(
			{ issuer: TEST_ISSUER, signingKey: privateKey },
			db,
			stubGetUserClaims,
		);
	});

	it("registers a client and returns clientId + clientSecret", async () => {
		const result = await mod.registerClient({
			clientName: "My App",
			redirectUris: ["https://app.example.com/callback"],
		});
		expect(result.success).toBe(true);
		if (!result.success) return;

		expect(result.data.clientId).toMatch(/^[0-9a-f]{32}$/);
		expect(result.data.clientSecret).toMatch(/^[0-9a-f]{64}$/);
		expect(result.data.clientName).toBe("My App");
		expect(result.data.redirectUris).toEqual(["https://app.example.com/callback"]);
		expect(result.data.grantTypes).toContain("authorization_code");
		expect(result.data.responseTypes).toContain("code");
	});

	it("rejects empty clientName", async () => {
		const result = await mod.registerClient({
			clientName: "",
			redirectUris: ["https://app.example.com/callback"],
		});
		expect(result.success).toBe(false);
		if (result.success) return;
		expect(result.error.code).toBe("INVALID_INPUT");
	});

	it("rejects empty redirectUris array", async () => {
		const result = await mod.registerClient({
			clientName: "App",
			redirectUris: [],
		});
		expect(result.success).toBe(false);
		if (result.success) return;
		expect(result.error.code).toBe("INVALID_INPUT");
	});

	it("rejects invalid redirect URI", async () => {
		const result = await mod.registerClient({
			clientName: "App",
			redirectUris: ["not-a-url"],
		});
		expect(result.success).toBe(false);
		if (result.success) return;
		expect(result.error.code).toBe("INVALID_INPUT");
	});

	it("generates unique clientIds for each registration", async () => {
		const a = await mod.registerClient({
			clientName: "App A",
			redirectUris: ["https://a.example.com/callback"],
		});
		const b = await mod.registerClient({
			clientName: "App B",
			redirectUris: ["https://b.example.com/callback"],
		});
		expect(a.success).toBe(true);
		expect(b.success).toBe(true);
		if (!a.success || !b.success) return;
		expect(a.data.clientId).not.toBe(b.data.clientId);
	});
});

// ---------------------------------------------------------------------------
// Client retrieval
// ---------------------------------------------------------------------------

describe("OidcProvider.getClient", () => {
	let db: Database;
	let mod: OidcProviderModule;

	beforeEach(async () => {
		db = await createTestDb();
		const { privateKey } = await createTestKeyPair();
		mod = createOidcProviderModule(
			{ issuer: TEST_ISSUER, signingKey: privateKey },
			db,
			stubGetUserClaims,
		);
	});

	it("retrieves a registered client by clientId", async () => {
		const reg = await registerTestClient(mod);
		const result = await mod.getClient(reg.clientId);
		expect(result.success).toBe(true);
		if (!result.success) return;
		expect(result.data.clientId).toBe(reg.clientId);
		expect(result.data.clientName).toBe("Test App");
	});

	it("does not expose clientSecret on retrieval", async () => {
		const reg = await registerTestClient(mod);
		const result = await mod.getClient(reg.clientId);
		expect(result.success).toBe(true);
		if (!result.success) return;
		expect(result.data.clientSecret).toBeNull();
	});

	it("returns error for unknown clientId", async () => {
		const result = await mod.getClient("nonexistent");
		expect(result.success).toBe(false);
		if (result.success) return;
		expect(result.error.code).toBe("CLIENT_NOT_FOUND");
	});

	it("returns error for empty clientId", async () => {
		const result = await mod.getClient("");
		expect(result.success).toBe(false);
		if (result.success) return;
		expect(result.error.code).toBe("INVALID_INPUT");
	});
});

// ---------------------------------------------------------------------------
// Client deletion
// ---------------------------------------------------------------------------

describe("OidcProvider.deleteClient", () => {
	let db: Database;
	let mod: OidcProviderModule;

	beforeEach(async () => {
		db = await createTestDb();
		const { privateKey } = await createTestKeyPair();
		mod = createOidcProviderModule(
			{ issuer: TEST_ISSUER, signingKey: privateKey },
			db,
			stubGetUserClaims,
		);
	});

	it("deletes an existing client", async () => {
		const reg = await registerTestClient(mod);
		const result = await mod.deleteClient(reg.clientId);
		expect(result.success).toBe(true);

		const getResult = await mod.getClient(reg.clientId);
		expect(getResult.success).toBe(false);
	});

	it("returns error for unknown clientId", async () => {
		const result = await mod.deleteClient("nonexistent");
		expect(result.success).toBe(false);
		if (result.success) return;
		expect(result.error.code).toBe("CLIENT_NOT_FOUND");
	});

	it("returns error for empty clientId", async () => {
		const result = await mod.deleteClient("");
		expect(result.success).toBe(false);
		if (result.success) return;
		expect(result.error.code).toBe("INVALID_INPUT");
	});
});

// ---------------------------------------------------------------------------
// Authorization
// ---------------------------------------------------------------------------

describe("OidcProvider.authorize", () => {
	let db: Database;
	let mod: OidcProviderModule;

	beforeEach(async () => {
		db = await createTestDb();
		const { privateKey } = await createTestKeyPair();
		mod = createOidcProviderModule(
			{ issuer: TEST_ISSUER, signingKey: privateKey },
			db,
			stubGetUserClaims,
		);
	});

	it("generates an authorization code", async () => {
		const client = await registerTestClient(mod);
		const result = await mod.authorize({
			clientId: client.clientId,
			redirectUri: "https://app.example.com/callback",
			responseType: "code",
			scope: "openid",
			userId: "user-1",
		});
		expect(result.success).toBe(true);
		if (!result.success) return;
		expect(result.data.code).toMatch(/^[0-9a-f]{64}$/);
	});

	it("passes through state parameter", async () => {
		const client = await registerTestClient(mod);
		const result = await mod.authorize({
			clientId: client.clientId,
			redirectUri: "https://app.example.com/callback",
			responseType: "code",
			scope: "openid",
			state: "my-state-value",
			userId: "user-1",
		});
		expect(result.success).toBe(true);
		if (!result.success) return;
		expect(result.data.state).toBe("my-state-value");
	});

	it("rejects unknown client", async () => {
		const result = await mod.authorize({
			clientId: "nonexistent",
			redirectUri: "https://app.example.com/callback",
			responseType: "code",
			scope: "openid",
			userId: "user-1",
		});
		expect(result.success).toBe(false);
		if (result.success) return;
		expect(result.error.code).toBe("CLIENT_NOT_FOUND");
	});

	it("rejects unregistered redirect_uri", async () => {
		const client = await registerTestClient(mod);
		const result = await mod.authorize({
			clientId: client.clientId,
			redirectUri: "https://evil.example.com/callback",
			responseType: "code",
			scope: "openid",
			userId: "user-1",
		});
		expect(result.success).toBe(false);
		if (result.success) return;
		expect(result.error.code).toBe("INVALID_REDIRECT_URI");
	});

	it("rejects unsupported scope", async () => {
		const client = await registerTestClient(mod);
		const result = await mod.authorize({
			clientId: client.clientId,
			redirectUri: "https://app.example.com/callback",
			responseType: "code",
			scope: "openid admin:nuclear",
			userId: "user-1",
		});
		expect(result.success).toBe(false);
		if (result.success) return;
		expect(result.error.code).toBe("INVALID_SCOPE");
	});

	it("rejects invalid response_type", async () => {
		const client = await registerTestClient(mod);
		const result = await mod.authorize({
			clientId: client.clientId,
			redirectUri: "https://app.example.com/callback",
			responseType: "token" as "code",
			scope: "openid",
			userId: "user-1",
		});
		expect(result.success).toBe(false);
		if (result.success) return;
		expect(result.error.code).toBe("INVALID_INPUT");
	});
});

// ---------------------------------------------------------------------------
// Token exchange (authorization_code grant)
// ---------------------------------------------------------------------------

describe("OidcProvider.exchangeToken (authorization_code)", () => {
	let db: Database;
	let mod: OidcProviderModule;

	beforeEach(async () => {
		db = await createTestDb();
		const { privateKey } = await createTestKeyPair();
		mod = createOidcProviderModule(
			{ issuer: TEST_ISSUER, signingKey: privateKey },
			db,
			stubGetUserClaims,
		);
	});

	it("exchanges code for access_token, id_token, and refresh_token", async () => {
		const client = await registerTestClient(mod);
		const { tokenResult } = await runAuthCodeFlow(mod, {
			clientId: client.clientId,
			clientSecret: client.clientSecret,
		});

		expect(tokenResult.success).toBe(true);
		if (!tokenResult.success) return;

		expect(tokenResult.data.accessToken).toBeTruthy();
		expect(tokenResult.data.idToken).toBeTruthy();
		expect(tokenResult.data.refreshToken).toBeTruthy();
		expect(tokenResult.data.tokenType).toBe("Bearer");
		expect(tokenResult.data.expiresIn).toBe(3600);
	});

	it("fails with an invalid authorization code", async () => {
		const client = await registerTestClient(mod);
		const result = await mod.exchangeToken({
			grantType: "authorization_code",
			code: "a".repeat(64),
			redirectUri: "https://app.example.com/callback",
			clientId: client.clientId,
			clientSecret: client.clientSecret ?? undefined,
		});
		expect(result.success).toBe(false);
		if (result.success) return;
		expect(result.error.code).toBe("INVALID_CODE");
	});

	it("fails when code is reused", async () => {
		const client = await registerTestClient(mod);
		const authorizeResult = await mod.authorize({
			clientId: client.clientId,
			redirectUri: "https://app.example.com/callback",
			responseType: "code",
			scope: "openid",
			userId: "user-1",
		});
		expect(authorizeResult.success).toBe(true);
		if (!authorizeResult.success) return;

		// First exchange succeeds
		const first = await mod.exchangeToken({
			grantType: "authorization_code",
			code: authorizeResult.data.code,
			redirectUri: "https://app.example.com/callback",
			clientId: client.clientId,
			clientSecret: client.clientSecret ?? undefined,
		});
		expect(first.success).toBe(true);

		// Second exchange fails
		const second = await mod.exchangeToken({
			grantType: "authorization_code",
			code: authorizeResult.data.code,
			redirectUri: "https://app.example.com/callback",
			clientId: client.clientId,
			clientSecret: client.clientSecret ?? undefined,
		});
		expect(second.success).toBe(false);
		if (second.success) return;
		expect(second.error.code).toBe("CODE_ALREADY_USED");
	});

	it("fails when redirect_uri does not match", async () => {
		const client = await registerTestClient(mod);
		const authorizeResult = await mod.authorize({
			clientId: client.clientId,
			redirectUri: "https://app.example.com/callback",
			responseType: "code",
			scope: "openid",
			userId: "user-1",
		});
		expect(authorizeResult.success).toBe(true);
		if (!authorizeResult.success) return;

		const result = await mod.exchangeToken({
			grantType: "authorization_code",
			code: authorizeResult.data.code,
			redirectUri: "https://different.example.com/callback",
			clientId: client.clientId,
			clientSecret: client.clientSecret ?? undefined,
		});
		expect(result.success).toBe(false);
		if (result.success) return;
		expect(result.error.code).toBe("REDIRECT_URI_MISMATCH");
	});

	it("fails when client_secret is missing", async () => {
		const client = await registerTestClient(mod);
		const authorizeResult = await mod.authorize({
			clientId: client.clientId,
			redirectUri: "https://app.example.com/callback",
			responseType: "code",
			scope: "openid",
			userId: "user-1",
		});
		expect(authorizeResult.success).toBe(true);
		if (!authorizeResult.success) return;

		const result = await mod.exchangeToken({
			grantType: "authorization_code",
			code: authorizeResult.data.code,
			redirectUri: "https://app.example.com/callback",
			clientId: client.clientId,
			// No clientSecret
		});
		expect(result.success).toBe(false);
		if (result.success) return;
		expect(result.error.code).toBe("CLIENT_AUTH_REQUIRED");
	});

	it("fails when client_secret is wrong", async () => {
		const client = await registerTestClient(mod);
		const authorizeResult = await mod.authorize({
			clientId: client.clientId,
			redirectUri: "https://app.example.com/callback",
			responseType: "code",
			scope: "openid",
			userId: "user-1",
		});
		expect(authorizeResult.success).toBe(true);
		if (!authorizeResult.success) return;

		const result = await mod.exchangeToken({
			grantType: "authorization_code",
			code: authorizeResult.data.code,
			redirectUri: "https://app.example.com/callback",
			clientId: client.clientId,
			clientSecret: "wrong-secret",
		});
		expect(result.success).toBe(false);
		if (result.success) return;
		expect(result.error.code).toBe("INVALID_CLIENT_SECRET");
	});

	it("fails when client_id does not match the code", async () => {
		const clientA = await registerTestClient(mod);
		const clientB = await mod.registerClient({
			clientName: "Other App",
			redirectUris: ["https://other.example.com/callback"],
		});
		expect(clientB.success).toBe(true);
		if (!clientB.success) return;

		const authorizeResult = await mod.authorize({
			clientId: clientA.clientId,
			redirectUri: "https://app.example.com/callback",
			responseType: "code",
			scope: "openid",
			userId: "user-1",
		});
		expect(authorizeResult.success).toBe(true);
		if (!authorizeResult.success) return;

		const result = await mod.exchangeToken({
			grantType: "authorization_code",
			code: authorizeResult.data.code,
			redirectUri: "https://app.example.com/callback",
			clientId: clientB.data.clientId,
			clientSecret: clientB.data.clientSecret ?? undefined,
		});
		expect(result.success).toBe(false);
		if (result.success) return;
		expect(result.error.code).toBe("CLIENT_MISMATCH");
	});
});

// ---------------------------------------------------------------------------
// Token exchange with PKCE
// ---------------------------------------------------------------------------

describe("OidcProvider.exchangeToken (PKCE)", () => {
	let db: Database;
	let mod: OidcProviderModule;

	beforeEach(async () => {
		db = await createTestDb();
		const { privateKey } = await createTestKeyPair();
		mod = createOidcProviderModule(
			{ issuer: TEST_ISSUER, signingKey: privateKey },
			db,
			stubGetUserClaims,
		);
	});

	it("succeeds with valid PKCE code_verifier", async () => {
		const client = await registerTestClient(mod);
		const pkce = await generatePkce();
		const { tokenResult } = await runAuthCodeFlow(mod, {
			clientId: client.clientId,
			clientSecret: client.clientSecret,
			pkce,
		});

		expect(tokenResult.success).toBe(true);
		if (!tokenResult.success) return;
		expect(tokenResult.data.accessToken).toBeTruthy();
	});

	it("fails with wrong code_verifier", async () => {
		const client = await registerTestClient(mod);
		const pkce = await generatePkce();

		const authorizeResult = await mod.authorize({
			clientId: client.clientId,
			redirectUri: "https://app.example.com/callback",
			responseType: "code",
			scope: "openid",
			codeChallenge: pkce.codeChallenge,
			codeChallengeMethod: "S256",
			userId: "user-1",
		});
		expect(authorizeResult.success).toBe(true);
		if (!authorizeResult.success) return;

		const result = await mod.exchangeToken({
			grantType: "authorization_code",
			code: authorizeResult.data.code,
			redirectUri: "https://app.example.com/callback",
			codeVerifier: "wrong-verifier-that-is-at-least-43-characters-long-for-testing",
			clientId: client.clientId,
			clientSecret: client.clientSecret ?? undefined,
		});
		expect(result.success).toBe(false);
		if (result.success) return;
		expect(result.error.code).toBe("PKCE_MISMATCH");
	});

	it("fails when code_verifier is missing but code_challenge was set", async () => {
		const client = await registerTestClient(mod);
		const pkce = await generatePkce();

		const authorizeResult = await mod.authorize({
			clientId: client.clientId,
			redirectUri: "https://app.example.com/callback",
			responseType: "code",
			scope: "openid",
			codeChallenge: pkce.codeChallenge,
			codeChallengeMethod: "S256",
			userId: "user-1",
		});
		expect(authorizeResult.success).toBe(true);
		if (!authorizeResult.success) return;

		const result = await mod.exchangeToken({
			grantType: "authorization_code",
			code: authorizeResult.data.code,
			redirectUri: "https://app.example.com/callback",
			// No codeVerifier
			clientId: client.clientId,
			clientSecret: client.clientSecret ?? undefined,
		});
		expect(result.success).toBe(false);
		if (result.success) return;
		expect(result.error.code).toBe("PKCE_REQUIRED");
	});
});

// ---------------------------------------------------------------------------
// Token refresh
// ---------------------------------------------------------------------------

describe("OidcProvider.exchangeToken (refresh_token)", () => {
	let db: Database;
	let mod: OidcProviderModule;

	beforeEach(async () => {
		db = await createTestDb();
		const { privateKey } = await createTestKeyPair();
		mod = createOidcProviderModule(
			{ issuer: TEST_ISSUER, signingKey: privateKey },
			db,
			stubGetUserClaims,
		);
	});

	it("refreshes tokens and returns a new token set", async () => {
		const client = await registerTestClient(mod);
		const { tokenResult: initial } = await runAuthCodeFlow(mod, {
			clientId: client.clientId,
			clientSecret: client.clientSecret,
		});
		expect(initial.success).toBe(true);
		if (!initial.success) return;

		const refresh = await mod.exchangeToken({
			grantType: "refresh_token",
			refreshToken: initial.data.refreshToken,
			clientId: client.clientId,
			clientSecret: client.clientSecret ?? undefined,
		});
		expect(refresh.success).toBe(true);
		if (!refresh.success) return;

		expect(refresh.data.accessToken).toBeTruthy();
		expect(refresh.data.refreshToken).toBeTruthy();
		// New refresh token should differ from old one (rotation)
		expect(refresh.data.refreshToken).not.toBe(initial.data.refreshToken);
	});

	it("revokes old refresh token after rotation", async () => {
		const client = await registerTestClient(mod);
		const { tokenResult: initial } = await runAuthCodeFlow(mod, {
			clientId: client.clientId,
			clientSecret: client.clientSecret,
		});
		expect(initial.success).toBe(true);
		if (!initial.success) return;

		// Use the refresh token once
		const refresh1 = await mod.exchangeToken({
			grantType: "refresh_token",
			refreshToken: initial.data.refreshToken,
			clientId: client.clientId,
			clientSecret: client.clientSecret ?? undefined,
		});
		expect(refresh1.success).toBe(true);

		// Attempt to reuse the old refresh token
		const refresh2 = await mod.exchangeToken({
			grantType: "refresh_token",
			refreshToken: initial.data.refreshToken,
			clientId: client.clientId,
			clientSecret: client.clientSecret ?? undefined,
		});
		expect(refresh2.success).toBe(false);
		if (refresh2.success) return;
		expect(refresh2.error.code).toBe("REFRESH_TOKEN_REVOKED");
	});

	it("fails with invalid refresh token", async () => {
		const client = await registerTestClient(mod);
		const result = await mod.exchangeToken({
			grantType: "refresh_token",
			refreshToken: "nonexistent-token",
			clientId: client.clientId,
			clientSecret: client.clientSecret ?? undefined,
		});
		expect(result.success).toBe(false);
		if (result.success) return;
		expect(result.error.code).toBe("INVALID_REFRESH_TOKEN");
	});

	it("fails when client_id does not match the refresh token", async () => {
		const clientA = await registerTestClient(mod);
		const clientB = await mod.registerClient({
			clientName: "Other App",
			redirectUris: ["https://other.example.com/callback"],
		});
		expect(clientB.success).toBe(true);
		if (!clientB.success) return;

		const { tokenResult } = await runAuthCodeFlow(mod, {
			clientId: clientA.clientId,
			clientSecret: clientA.clientSecret,
		});
		expect(tokenResult.success).toBe(true);
		if (!tokenResult.success) return;

		const result = await mod.exchangeToken({
			grantType: "refresh_token",
			refreshToken: tokenResult.data.refreshToken,
			clientId: clientB.data.clientId,
			clientSecret: clientB.data.clientSecret ?? undefined,
		});
		expect(result.success).toBe(false);
		if (result.success) return;
		expect(result.error.code).toBe("CLIENT_MISMATCH");
	});
});

// ---------------------------------------------------------------------------
// ID token claims
// ---------------------------------------------------------------------------

describe("OidcProvider ID token claims", () => {
	let db: Database;
	let mod: OidcProviderModule;

	beforeEach(async () => {
		db = await createTestDb();
		const { privateKey } = await createTestKeyPair();
		mod = createOidcProviderModule(
			{ issuer: TEST_ISSUER, signingKey: privateKey },
			db,
			stubGetUserClaims,
		);
	});

	it("contains sub, iss, aud, iat, exp", async () => {
		const client = await registerTestClient(mod);
		const { tokenResult } = await runAuthCodeFlow(mod, {
			clientId: client.clientId,
			clientSecret: client.clientSecret,
			userId: "user-42",
		});
		expect(tokenResult.success).toBe(true);
		if (!tokenResult.success) return;

		const jwks = await mod.getJwks();
		const firstKey = jwks.keys[0];
		if (!firstKey) throw new Error("No key in JWKS");
		const key = await jose.importJWK(firstKey, "RS256");
		const { payload } = await jose.jwtVerify(tokenResult.data.idToken, key, {
			issuer: TEST_ISSUER,
		});

		expect(payload.sub).toBe("user-42");
		expect(payload.iss).toBe(TEST_ISSUER);
		expect(payload.aud).toBe(client.clientId);
		expect(payload.iat).toBeTypeOf("number");
		expect(payload.exp).toBeTypeOf("number");
	});

	it("includes nonce when provided", async () => {
		const client = await registerTestClient(mod);
		const { tokenResult } = await runAuthCodeFlow(mod, {
			clientId: client.clientId,
			clientSecret: client.clientSecret,
			nonce: "test-nonce-123",
		});
		expect(tokenResult.success).toBe(true);
		if (!tokenResult.success) return;

		const jwks = await mod.getJwks();
		const firstKey = jwks.keys[0];
		if (!firstKey) throw new Error("No key in JWKS");
		const key = await jose.importJWK(firstKey, "RS256");
		const { payload } = await jose.jwtVerify(tokenResult.data.idToken, key, {
			issuer: TEST_ISSUER,
		});

		expect((payload as Record<string, unknown>).nonce).toBe("test-nonce-123");
	});

	it("includes at_hash claim", async () => {
		const client = await registerTestClient(mod);
		const { tokenResult } = await runAuthCodeFlow(mod, {
			clientId: client.clientId,
			clientSecret: client.clientSecret,
		});
		expect(tokenResult.success).toBe(true);
		if (!tokenResult.success) return;

		const jwks = await mod.getJwks();
		const firstKey = jwks.keys[0];
		if (!firstKey) throw new Error("No key in JWKS");
		const key = await jose.importJWK(firstKey, "RS256");
		const { payload } = await jose.jwtVerify(tokenResult.data.idToken, key, {
			issuer: TEST_ISSUER,
		});

		expect((payload as Record<string, unknown>).at_hash).toBeTruthy();

		// Verify at_hash value
		const atHashBuffer = createHash("sha256").update(tokenResult.data.accessToken).digest();
		const expectedAtHash = jose.base64url.encode(atHashBuffer.subarray(0, atHashBuffer.length / 2));
		expect((payload as Record<string, unknown>).at_hash).toBe(expectedAtHash);
	});

	it("includes email and profile claims based on scopes", async () => {
		const client = await registerTestClient(mod);
		const { tokenResult } = await runAuthCodeFlow(mod, {
			clientId: client.clientId,
			clientSecret: client.clientSecret,
			scopes: "openid email profile",
			userId: "alice",
		});
		expect(tokenResult.success).toBe(true);
		if (!tokenResult.success) return;

		const jwks = await mod.getJwks();
		const firstKey = jwks.keys[0];
		if (!firstKey) throw new Error("No key in JWKS");
		const key = await jose.importJWK(firstKey, "RS256");
		const { payload } = await jose.jwtVerify(tokenResult.data.idToken, key, {
			issuer: TEST_ISSUER,
		});

		expect((payload as Record<string, unknown>).email).toBe("alice@example.com");
		expect((payload as Record<string, unknown>).name).toBe("User alice");
	});

	it("includes azp (authorized party) claim", async () => {
		const client = await registerTestClient(mod);
		const { tokenResult } = await runAuthCodeFlow(mod, {
			clientId: client.clientId,
			clientSecret: client.clientSecret,
		});
		expect(tokenResult.success).toBe(true);
		if (!tokenResult.success) return;

		const jwks = await mod.getJwks();
		const firstKey = jwks.keys[0];
		if (!firstKey) throw new Error("No key in JWKS");
		const key = await jose.importJWK(firstKey, "RS256");
		const { payload } = await jose.jwtVerify(tokenResult.data.idToken, key, {
			issuer: TEST_ISSUER,
		});

		expect((payload as Record<string, unknown>).azp).toBe(client.clientId);
	});
});

// ---------------------------------------------------------------------------
// UserInfo
// ---------------------------------------------------------------------------

describe("OidcProvider.getUserInfo", () => {
	let db: Database;
	let mod: OidcProviderModule;

	beforeEach(async () => {
		db = await createTestDb();
		const { privateKey } = await createTestKeyPair();
		mod = createOidcProviderModule(
			{ issuer: TEST_ISSUER, signingKey: privateKey },
			db,
			stubGetUserClaims,
		);
	});

	it("returns user claims for a valid access token", async () => {
		const client = await registerTestClient(mod);
		const { tokenResult } = await runAuthCodeFlow(mod, {
			clientId: client.clientId,
			clientSecret: client.clientSecret,
			userId: "bob",
			scopes: "openid email profile",
		});
		expect(tokenResult.success).toBe(true);
		if (!tokenResult.success) return;

		const result = await mod.getUserInfo(tokenResult.data.accessToken);
		expect(result.success).toBe(true);
		if (!result.success) return;

		expect(result.data.sub).toBe("bob");
		expect(result.data.email).toBe("bob@example.com");
		expect(result.data.name).toBe("User bob");
	});

	it("fails with invalid access token", async () => {
		const result = await mod.getUserInfo("invalid-jwt-token");
		expect(result.success).toBe(false);
		if (result.success) return;
		expect(result.error.code).toBe("TOKEN_VALIDATION_FAILED");
	});

	it("fails with empty access token", async () => {
		const result = await mod.getUserInfo("");
		expect(result.success).toBe(false);
		if (result.success) return;
		expect(result.error.code).toBe("INVALID_INPUT");
	});
});

// ---------------------------------------------------------------------------
// Discovery document
// ---------------------------------------------------------------------------

describe("OidcProvider.getDiscoveryDocument", () => {
	let mod: OidcProviderModule;

	beforeEach(async () => {
		const db = await createTestDb();
		const { privateKey } = await createTestKeyPair();
		mod = createOidcProviderModule(
			{ issuer: TEST_ISSUER, signingKey: privateKey },
			db,
			stubGetUserClaims,
		);
	});

	it("returns a well-formed OIDC discovery document", () => {
		const doc = mod.getDiscoveryDocument();

		expect(doc.issuer).toBe(TEST_ISSUER);
		expect(doc.authorization_endpoint).toBe(`${TEST_ISSUER}/authorize`);
		expect(doc.token_endpoint).toBe(`${TEST_ISSUER}/token`);
		expect(doc.userinfo_endpoint).toBe(`${TEST_ISSUER}/userinfo`);
		expect(doc.jwks_uri).toBe(`${TEST_ISSUER}/.well-known/jwks.json`);
		expect(doc.registration_endpoint).toBe(`${TEST_ISSUER}/register`);
	});

	it("includes supported scopes", () => {
		const doc = mod.getDiscoveryDocument();
		expect(doc.scopes_supported).toContain("openid");
		expect(doc.scopes_supported).toContain("profile");
		expect(doc.scopes_supported).toContain("email");
	});

	it("includes supported response_types", () => {
		const doc = mod.getDiscoveryDocument();
		expect(doc.response_types_supported).toContain("code");
	});

	it("includes supported grant_types", () => {
		const doc = mod.getDiscoveryDocument();
		expect(doc.grant_types_supported).toContain("authorization_code");
		expect(doc.grant_types_supported).toContain("refresh_token");
	});

	it("includes code_challenge_methods_supported", () => {
		const doc = mod.getDiscoveryDocument();
		expect(doc.code_challenge_methods_supported).toContain("S256");
	});

	it("includes claims_supported", () => {
		const doc = mod.getDiscoveryDocument();
		expect(doc.claims_supported).toContain("sub");
		expect(doc.claims_supported).toContain("email");
		expect(doc.claims_supported).toContain("name");
		expect(doc.claims_supported).toContain("nonce");
	});

	it("includes id_token_signing_alg_values_supported", () => {
		const doc = mod.getDiscoveryDocument();
		expect(doc.id_token_signing_alg_values_supported).toContain("RS256");
	});

	it("uses custom scopes when configured", async () => {
		const db = await createTestDb();
		const { privateKey } = await createTestKeyPair();
		const customMod = createOidcProviderModule(
			{
				issuer: TEST_ISSUER,
				signingKey: privateKey,
				supportedScopes: ["openid", "profile", "email", "phone"],
			},
			db,
			stubGetUserClaims,
		);
		const doc = customMod.getDiscoveryDocument();
		expect(doc.scopes_supported).toContain("phone");
	});
});

// ---------------------------------------------------------------------------
// JWKS
// ---------------------------------------------------------------------------

describe("OidcProvider.getJwks", () => {
	let mod: OidcProviderModule;

	beforeEach(async () => {
		const db = await createTestDb();
		const { privateKey } = await createTestKeyPair();
		mod = createOidcProviderModule(
			{ issuer: TEST_ISSUER, signingKey: privateKey },
			db,
			stubGetUserClaims,
		);
	});

	it("returns a JWKS with one key", async () => {
		const jwks = await mod.getJwks();
		expect(jwks.keys).toHaveLength(1);
	});

	it("returned key has kid, alg, use, kty fields", async () => {
		const jwks = await mod.getJwks();
		const firstKey = jwks.keys[0];
		if (!firstKey) throw new Error("No key in JWKS");
		const key = firstKey;
		expect(key.kid).toBe("theauth-oidc-1");
		expect(key.alg).toBe("RS256");
		expect(key.use).toBe("sig");
		expect(key.kty).toBe("RSA");
	});

	it("returned key does not contain private key material", async () => {
		const jwks = await mod.getJwks();
		const firstKey = jwks.keys[0];
		if (!firstKey) throw new Error("No key in JWKS");
		const key = firstKey;
		expect(key.d).toBeUndefined();
		expect(key.p).toBeUndefined();
		expect(key.q).toBeUndefined();
		expect(key.dp).toBeUndefined();
		expect(key.dq).toBeUndefined();
		expect(key.qi).toBeUndefined();
	});

	it("can be used to verify access tokens", async () => {
		const db = await createTestDb();
		const { privateKey } = await createTestKeyPair();
		const oidc = createOidcProviderModule(
			{ issuer: TEST_ISSUER, signingKey: privateKey },
			db,
			stubGetUserClaims,
		);

		const client = await registerTestClient(oidc);
		const { tokenResult } = await runAuthCodeFlow(oidc, {
			clientId: client.clientId,
			clientSecret: client.clientSecret,
		});
		expect(tokenResult.success).toBe(true);
		if (!tokenResult.success) return;

		const jwks = await oidc.getJwks();
		const firstKey = jwks.keys[0];
		if (!firstKey) throw new Error("No key in JWKS");
		const key = await jose.importJWK(firstKey, "RS256");
		const { payload } = await jose.jwtVerify(tokenResult.data.accessToken, key, {
			issuer: TEST_ISSUER,
		});

		expect(payload.sub).toBe("user-1");
		expect(payload.iss).toBe(TEST_ISSUER);
	});
});

// ---------------------------------------------------------------------------
// Access token validation
// ---------------------------------------------------------------------------

describe("OidcProvider.validateAccessToken", () => {
	let db: Database;
	let mod: OidcProviderModule;

	beforeEach(async () => {
		db = await createTestDb();
		const { privateKey } = await createTestKeyPair();
		mod = createOidcProviderModule(
			{ issuer: TEST_ISSUER, signingKey: privateKey },
			db,
			stubGetUserClaims,
		);
	});

	it("validates a valid access token", async () => {
		const client = await registerTestClient(mod);
		const { tokenResult } = await runAuthCodeFlow(mod, {
			clientId: client.clientId,
			clientSecret: client.clientSecret,
			userId: "user-99",
		});
		expect(tokenResult.success).toBe(true);
		if (!tokenResult.success) return;

		const result = await mod.validateAccessToken(tokenResult.data.accessToken);
		expect(result.success).toBe(true);
		if (!result.success) return;

		expect(result.data.sub).toBe("user-99");
		expect(result.data.iss).toBe(TEST_ISSUER);
		expect(result.data.clientId).toBe(client.clientId);
		expect(result.data.scope).toContain("openid");
	});

	it("fails with an expired access token", async () => {
		const { privateKey } = await createTestKeyPair();
		const shortLivedMod = createOidcProviderModule(
			{
				issuer: TEST_ISSUER,
				signingKey: privateKey,
				accessTokenTtl: -1, // Already expired when issued
			},
			db,
			stubGetUserClaims,
		);

		const client = await registerTestClient(shortLivedMod);
		const { tokenResult } = await runAuthCodeFlow(shortLivedMod, {
			clientId: client.clientId,
			clientSecret: client.clientSecret,
		});
		expect(tokenResult.success).toBe(true);
		if (!tokenResult.success) return;

		// Token is immediately expired
		const result = await shortLivedMod.validateAccessToken(tokenResult.data.accessToken);
		expect(result.success).toBe(false);
		if (result.success) return;
		expect(result.error.code).toBe("TOKEN_EXPIRED");
	});

	it("fails with a malformed token", async () => {
		const result = await mod.validateAccessToken("not-a-jwt");
		expect(result.success).toBe(false);
		if (result.success) return;
		expect(result.error.code).toBe("TOKEN_VALIDATION_FAILED");
	});

	it("fails with empty token", async () => {
		const result = await mod.validateAccessToken("");
		expect(result.success).toBe(false);
		if (result.success) return;
		expect(result.error.code).toBe("INVALID_INPUT");
	});

	it("fails with token signed by a different key", async () => {
		const { privateKey: otherKey } = await createTestKeyPair();
		const fakeToken = await new jose.SignJWT({ scope: "openid", client_id: "fake" })
			.setProtectedHeader({ alg: "RS256" })
			.setIssuer(TEST_ISSUER)
			.setSubject("attacker")
			.setExpirationTime("1h")
			.sign(otherKey);

		const result = await mod.validateAccessToken(fakeToken);
		expect(result.success).toBe(false);
		if (result.success) return;
		expect(result.error.code).toBe("TOKEN_VALIDATION_FAILED");
	});
});

// ---------------------------------------------------------------------------
// Expired authorization code
// ---------------------------------------------------------------------------

describe("OidcProvider expired authorization code", () => {
	it("rejects an expired authorization code", async () => {
		const db = await createTestDb();
		const { privateKey } = await createTestKeyPair();
		const mod = createOidcProviderModule(
			{
				issuer: TEST_ISSUER,
				signingKey: privateKey,
				authCodeTtl: 0, // Expire immediately
			},
			db,
			stubGetUserClaims,
		);

		const client = await registerTestClient(mod);
		const authorizeResult = await mod.authorize({
			clientId: client.clientId,
			redirectUri: "https://app.example.com/callback",
			responseType: "code",
			scope: "openid",
			userId: "user-1",
		});
		expect(authorizeResult.success).toBe(true);
		if (!authorizeResult.success) return;

		const result = await mod.exchangeToken({
			grantType: "authorization_code",
			code: authorizeResult.data.code,
			redirectUri: "https://app.example.com/callback",
			clientId: client.clientId,
			clientSecret: client.clientSecret ?? undefined,
		});
		expect(result.success).toBe(false);
		if (result.success) return;
		expect(result.error.code).toBe("CODE_EXPIRED");
	});
});

// ---------------------------------------------------------------------------
// Config TTL overrides
// ---------------------------------------------------------------------------

describe("OidcProvider config overrides", () => {
	it("uses custom accessTokenTtl in expiresIn response", async () => {
		const db = await createTestDb();
		const { privateKey } = await createTestKeyPair();
		const mod = createOidcProviderModule(
			{
				issuer: TEST_ISSUER,
				signingKey: privateKey,
				accessTokenTtl: 7200,
			},
			db,
			stubGetUserClaims,
		);

		const client = await registerTestClient(mod);
		const { tokenResult } = await runAuthCodeFlow(mod, {
			clientId: client.clientId,
			clientSecret: client.clientSecret,
		});
		expect(tokenResult.success).toBe(true);
		if (!tokenResult.success) return;
		expect(tokenResult.data.expiresIn).toBe(7200);
	});
});

// ---------------------------------------------------------------------------
// JWK import (passing JWK object instead of CryptoKey)
// ---------------------------------------------------------------------------

describe("OidcProvider with JWK config", () => {
	it("works when signingKey is a JWK object", async () => {
		const db = await createTestDb();
		const { privateKey } = await createTestKeyPair();
		const jwk = await jose.exportJWK(privateKey);

		const mod = createOidcProviderModule(
			{ issuer: TEST_ISSUER, signingKey: jwk },
			db,
			stubGetUserClaims,
		);

		const client = await registerTestClient(mod);
		const { tokenResult } = await runAuthCodeFlow(mod, {
			clientId: client.clientId,
			clientSecret: client.clientSecret,
		});
		expect(tokenResult.success).toBe(true);
		if (!tokenResult.success) return;
		expect(tokenResult.data.accessToken).toBeTruthy();

		// Verify the token can be validated
		const validation = await mod.validateAccessToken(tokenResult.data.accessToken);
		expect(validation.success).toBe(true);
	});
});
