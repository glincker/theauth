/**
 * Tests for the OAuth 2.0 / OIDC provider module.
 *
 * Covers:
 * - PKCE: code verifier generation and S256 challenge derivation
 * - Google provider: authorization URL construction
 * - GitHub provider: authorization URL construction
 * - State storage: persist state on getAuthorizationUrl, reject unknown/expired states
 * - handleCallback: happy path with mocked token exchange and user info
 * - linkAccount: manual account linking
 * - findLinkedUser: look up linked user by provider + account ID
 */

import { eq } from "drizzle-orm";
import { beforeEach, describe, expect, it } from "vitest";
import { createOAuthModule } from "../src/auth/oauth/module.js";
import { deriveCodeChallenge, generateCodeVerifier } from "../src/auth/oauth/pkce.js";
import { createGithubProvider } from "../src/auth/oauth/providers/github.js";
import { createGoogleProvider } from "../src/auth/oauth/providers/google.js";
import { oauthStates } from "../src/auth/oauth/schema.js";
import type { OAuthProvider, OAuthTokens, OAuthUserInfo } from "../src/auth/oauth/types.js";
import type { Database } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import * as schema from "../src/db/schema.js";

// Test DB helper

async function createTestDb(): Promise<Database> {
	const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite");

	// OAuth tables are now created by createTables() migration.
	// Seed a user for FK-sensitive tests.
	db.insert(schema.users)
		.values({
			id: "user-oauth-test",
			email: "oauth-test@example.com",
			name: "OAuth Test User",
			createdAt: new Date(),
			updatedAt: new Date(),
		})
		.run();

	return db;
}

// Mock provider factory

function createMockProvider(
	id: string,
	tokenOverride?: Partial<OAuthTokens>,
	userInfoOverride?: Partial<OAuthUserInfo>,
): OAuthProvider {
	const defaultTokens: OAuthTokens = {
		accessToken: `access-${id}-token`,
		refreshToken: `refresh-${id}-token`,
		expiresIn: 3600,
		tokenType: "Bearer",
		raw: {},
	};

	const defaultUserInfo: OAuthUserInfo = {
		id: `${id}-user-123`,
		email: `user@${id}.example.com`,
		name: `${id} User`,
		avatar: `https://avatars.${id}.example.com/u/123`,
		raw: {},
	};

	const tokens = { ...defaultTokens, ...tokenOverride };
	const userInfo = { ...defaultUserInfo, ...userInfoOverride };

	return {
		id,
		name: id.charAt(0).toUpperCase() + id.slice(1),
		authorizationUrl: `https://${id}.example.com/auth`,
		tokenUrl: `https://${id}.example.com/token`,
		userInfoUrl: `https://${id}.example.com/userinfo`,
		scopes: ["openid", "email"],
		async getAuthorizationUrl(state, _codeVerifier, redirectUri) {
			return `https://${id}.example.com/auth?state=${state}&redirect_uri=${encodeURIComponent(redirectUri)}`;
		},
		async exchangeCode(_code, _codeVerifier, _redirectUri) {
			return tokens;
		},
		async getUserInfo(_accessToken) {
			return userInfo;
		},
	};
}

// PKCE

describe("PKCE", () => {
	it("generates a non-empty code verifier", () => {
		const verifier = generateCodeVerifier();
		expect(typeof verifier).toBe("string");
		expect(verifier.length).toBeGreaterThan(40);
	});

	it("generates unique code verifiers each call", () => {
		const a = generateCodeVerifier();
		const b = generateCodeVerifier();
		expect(a).not.toBe(b);
	});

	it("code verifier is base64url (no +, /, = characters)", () => {
		const verifier = generateCodeVerifier();
		expect(verifier).not.toMatch(/[+/=]/);
	});

	it("derives a non-empty S256 code challenge", async () => {
		const verifier = generateCodeVerifier();
		const challenge = await deriveCodeChallenge(verifier);
		expect(typeof challenge).toBe("string");
		expect(challenge.length).toBeGreaterThan(0);
	});

	it("same verifier always produces the same challenge", async () => {
		const verifier = generateCodeVerifier();
		const a = await deriveCodeChallenge(verifier);
		const b = await deriveCodeChallenge(verifier);
		expect(a).toBe(b);
	});

	it("different verifiers produce different challenges", async () => {
		const a = await deriveCodeChallenge(generateCodeVerifier());
		const b = await deriveCodeChallenge(generateCodeVerifier());
		expect(a).not.toBe(b);
	});

	it("S256 challenge matches RFC 7636 test vector", async () => {
		// RFC 7636 Appendix B example:
		// verifier  = dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
		// challenge = E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
		const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
		const challenge = await deriveCodeChallenge(verifier);
		expect(challenge).toBe("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
	});

	it("challenge is base64url encoded (no +, /, = characters)", async () => {
		const challenge = await deriveCodeChallenge(generateCodeVerifier());
		expect(challenge).not.toMatch(/[+/=]/);
	});
});

// Google provider

describe("Google provider", () => {
	const google = createGoogleProvider({
		clientId: "google-client-id",
		clientSecret: "google-client-secret",
	});

	it("has the correct provider ID", () => {
		expect(google.id).toBe("google");
	});

	it("includes default scopes", () => {
		expect(google.scopes).toContain("openid");
		expect(google.scopes).toContain("email");
		expect(google.scopes).toContain("profile");
	});

	it("merges extra scopes without duplicates", () => {
		const g = createGoogleProvider({
			clientId: "id",
			clientSecret: "secret",
			scopes: ["email", "https://www.googleapis.com/auth/drive.readonly"],
		});
		// "email" already in defaults — should not appear twice
		const emailCount = g.scopes.filter((s) => s === "email").length;
		expect(emailCount).toBe(1);
		expect(g.scopes).toContain("https://www.googleapis.com/auth/drive.readonly");
	});

	it("builds a valid authorization URL", async () => {
		const verifier = generateCodeVerifier();
		const url = await google.getAuthorizationUrl(
			"test-state",
			verifier,
			"https://app.example.com/callback",
		);

		expect(url).toContain("accounts.google.com");
		expect(url).toContain("client_id=google-client-id");
		expect(url).toContain("response_type=code");
		expect(url).toContain("state=test-state");
		expect(url).toContain("code_challenge_method=S256");
		expect(url).toContain("code_challenge=");
		expect(url).toContain("access_type=offline");
	});

	it("embeds the correct redirect URI", async () => {
		const verifier = generateCodeVerifier();
		const redirectUri = "https://app.example.com/callback";
		const url = await google.getAuthorizationUrl("state", verifier, redirectUri);
		expect(url).toContain(encodeURIComponent(redirectUri));
	});

	it("overrides redirect URI when configured", async () => {
		const g = createGoogleProvider({
			clientId: "id",
			clientSecret: "secret",
			redirectUri: "https://override.example.com/cb",
		});
		const url = await g.getAuthorizationUrl(
			"state",
			generateCodeVerifier(),
			"https://ignored.example.com/cb",
		);
		expect(url).toContain(encodeURIComponent("https://override.example.com/cb"));
		expect(url).not.toContain("ignored.example.com");
	});

	it("embeds a valid code challenge derived from the verifier", async () => {
		const verifier = generateCodeVerifier();
		const expectedChallenge = await deriveCodeChallenge(verifier);
		const url = await google.getAuthorizationUrl("state", verifier, "https://app.example.com/cb");
		expect(url).toContain(`code_challenge=${encodeURIComponent(expectedChallenge)}`);
	});
});

// GitHub provider

describe("GitHub provider", () => {
	const github = createGithubProvider({
		clientId: "github-client-id",
		clientSecret: "github-client-secret",
	});

	it("has the correct provider ID", () => {
		expect(github.id).toBe("github");
	});

	it("includes user:email in default scopes", () => {
		expect(github.scopes).toContain("user:email");
	});

	it("merges extra scopes", () => {
		const g = createGithubProvider({
			clientId: "id",
			clientSecret: "secret",
			scopes: ["read:org"],
		});
		expect(g.scopes).toContain("user:email");
		expect(g.scopes).toContain("read:org");
	});

	it("builds a valid authorization URL", async () => {
		const verifier = generateCodeVerifier();
		const url = await github.getAuthorizationUrl(
			"gh-state",
			verifier,
			"https://app.example.com/callback",
		);

		expect(url).toContain("github.com/login/oauth/authorize");
		expect(url).toContain("client_id=github-client-id");
		expect(url).toContain("state=gh-state");
	});

	it("embeds the redirect URI", async () => {
		const redirectUri = "https://app.example.com/callback";
		const url = await github.getAuthorizationUrl("state", generateCodeVerifier(), redirectUri);
		expect(url).toContain(encodeURIComponent(redirectUri));
	});

	it("embeds a code challenge for symmetry", async () => {
		const url = await github.getAuthorizationUrl(
			"state",
			generateCodeVerifier(),
			"https://app.example.com/cb",
		);
		expect(url).toContain("code_challenge=");
		expect(url).toContain("code_challenge_method=S256");
	});
});

// OAuth module — state management

describe("createOAuthModule — state management", () => {
	let db: Database;

	beforeEach(async () => {
		db = await createTestDb();
	});

	it("throws when the provider is not configured", async () => {
		const oauth = createOAuthModule(db, { providers: {} });
		await expect(oauth.getAuthorizationUrl("google", "https://app.example.com/cb")).rejects.toThrow(
			"not configured",
		);
	});

	it("persists a state row on getAuthorizationUrl", async () => {
		const mock = createMockProvider("test");
		const oauth = createOAuthModule(db, { providers: { test: mock } });

		const { state } = await oauth.getAuthorizationUrl("test", "https://app.example.com/cb");

		const rows = await db.select().from(oauthStates).where(eq(oauthStates.state, state));
		expect(rows).toHaveLength(1);
		expect(rows[0]?.provider).toBe("test");
		expect(rows[0]?.codeVerifier).toBeTruthy();
	});

	it("returns a unique state each call", async () => {
		const mock = createMockProvider("test");
		const oauth = createOAuthModule(db, { providers: { test: mock } });

		const { state: s1 } = await oauth.getAuthorizationUrl("test", "https://app.example.com/cb");
		const { state: s2 } = await oauth.getAuthorizationUrl("test", "https://app.example.com/cb");
		expect(s1).not.toBe(s2);
	});

	it("state entry expires after the configured TTL", async () => {
		const mock = createMockProvider("test");
		const oauth = createOAuthModule(db, {
			providers: { test: mock },
			stateTtlSeconds: 1,
		});

		const { state } = await oauth.getAuthorizationUrl("test", "https://app.example.com/cb");
		const rows = await db.select().from(oauthStates).where(eq(oauthStates.state, state));
		const expiresAt = rows[0]?.expiresAt;
		const nowish = new Date();
		// Should expire within ~2 seconds of now
		expect(expiresAt?.getTime()).toBeGreaterThan(nowish.getTime() - 1000);
		expect(expiresAt?.getTime()).toBeLessThanOrEqual(nowish.getTime() + 2000);
	});

	it("rejects an unknown state on callback", async () => {
		const mock = createMockProvider("test");
		const oauth = createOAuthModule(db, { providers: { test: mock } });

		await expect(
			oauth.handleCallback("test", "code", "nonexistent-state", "https://app.example.com/cb"),
		).rejects.toThrow("unknown or already-used");
	});

	it("rejects a state issued for a different provider", async () => {
		const mock = createMockProvider("test");
		const oauth = createOAuthModule(db, { providers: { test: mock } });

		const { state } = await oauth.getAuthorizationUrl("test", "https://app.example.com/cb");

		await expect(
			oauth.handleCallback("other", "code", state, "https://app.example.com/cb"),
		).rejects.toThrow("not");
	});

	it("rejects an expired state", async () => {
		const mock = createMockProvider("test");
		const oauth = createOAuthModule(db, { providers: { test: mock } });

		const { state } = await oauth.getAuthorizationUrl("test", "https://app.example.com/cb");

		// Manually backdate the expiry.
		await db
			.update(oauthStates)
			.set({ expiresAt: new Date(Date.now() - 1000) })
			.where(eq(oauthStates.state, state));

		await expect(
			oauth.handleCallback("test", "code", state, "https://app.example.com/cb"),
		).rejects.toThrow("expired");
	});

	it("consumes the state on successful callback (prevents replay)", async () => {
		const mock = createMockProvider("test");
		const oauth = createOAuthModule(db, { providers: { test: mock } });

		const { state } = await oauth.getAuthorizationUrl("test", "https://app.example.com/cb");

		// First callback succeeds.
		await oauth.handleCallback("test", "code", state, "https://app.example.com/cb");

		// State row should be gone.
		const remaining = await db.select().from(oauthStates).where(eq(oauthStates.state, state));
		expect(remaining).toHaveLength(0);

		// Replaying the same state should fail.
		await expect(
			oauth.handleCallback("test", "code", state, "https://app.example.com/cb"),
		).rejects.toThrow("unknown or already-used");
	});
});

// OAuth module — callback and account management

describe("createOAuthModule — handleCallback", () => {
	let db: Database;

	beforeEach(async () => {
		db = await createTestDb();
	});

	it("creates a new account row on first callback", async () => {
		const mock = createMockProvider("test");
		const oauth = createOAuthModule(db, { providers: { test: mock } });

		const { state } = await oauth.getAuthorizationUrl("test", "https://app.example.com/cb");
		const result = await oauth.handleCallback(
			"test",
			"auth-code",
			state,
			"https://app.example.com/cb",
		);

		expect(result.isNewAccount).toBe(true);
		expect(result.userInfo.email).toBe("user@test.example.com");
		expect(result.tokens.accessToken).toBe("access-test-token");
		expect(result.account.provider).toBe("test");
		expect(result.account.providerAccountId).toBe("test-user-123");
	});

	it("recognizes an existing account on subsequent callbacks", async () => {
		const mock = createMockProvider("test");
		const oauth = createOAuthModule(db, { providers: { test: mock } });

		// First callback
		const { state: s1 } = await oauth.getAuthorizationUrl("test", "https://app.example.com/cb");
		const first = await oauth.handleCallback("test", "code", s1, "https://app.example.com/cb");
		// Link the pending account to a real user.
		await oauth.linkAccount("user-oauth-test", "test", first.userInfo, first.tokens);

		// Second callback for the same provider account.
		const { state: s2 } = await oauth.getAuthorizationUrl("test", "https://app.example.com/cb");
		const second = await oauth.handleCallback("test", "code", s2, "https://app.example.com/cb");

		expect(second.isNewAccount).toBe(false);
		expect(second.account.id).toBe(first.account.id);
	});

	it("stores access and refresh tokens on the account row", async () => {
		const mock = createMockProvider("test");
		const oauth = createOAuthModule(db, { providers: { test: mock } });

		const { state } = await oauth.getAuthorizationUrl("test", "https://app.example.com/cb");
		const { account } = await oauth.handleCallback(
			"test",
			"code",
			state,
			"https://app.example.com/cb",
		);

		expect(account.accessToken).toBe("access-test-token");
		expect(account.refreshToken).toBe("refresh-test-token");
	});

	it("computes expiresAt from expiresIn", async () => {
		const mock = createMockProvider("test", { expiresIn: 3600 });
		const oauth = createOAuthModule(db, { providers: { test: mock } });

		const { state } = await oauth.getAuthorizationUrl("test", "https://app.example.com/cb");
		const { account } = await oauth.handleCallback(
			"test",
			"code",
			state,
			"https://app.example.com/cb",
		);

		expect(account.expiresAt).not.toBeNull();
		const diff = account.expiresAt?.getTime() - Date.now();
		// Should be roughly 1 hour (±5 s tolerance)
		expect(diff).toBeGreaterThan(3595_000);
		expect(diff).toBeLessThan(3605_000);
	});
});

// OAuth module — linkAccount and findLinkedUser

describe("createOAuthModule — linkAccount / findLinkedUser", () => {
	let db: Database;

	beforeEach(async () => {
		db = await createTestDb();
	});

	it("links an account to an existing user", async () => {
		const mock = createMockProvider("test");
		const oauth = createOAuthModule(db, { providers: { test: mock } });

		const userInfo: OAuthUserInfo = {
			id: "gh-456",
			email: "dev@example.com",
			name: "Dev User",
			raw: {},
		};
		const tokens: OAuthTokens = {
			accessToken: "at-123",
			tokenType: "Bearer",
			raw: {},
		};

		const account = await oauth.linkAccount("user-oauth-test", "test", userInfo, tokens);

		expect(account.userId).toBe("user-oauth-test");
		expect(account.provider).toBe("test");
		expect(account.providerAccountId).toBe("gh-456");
		expect(account.accessToken).toBe("at-123");
	});

	it("findLinkedUser returns the user after linking", async () => {
		const mock = createMockProvider("test");
		const oauth = createOAuthModule(db, { providers: { test: mock } });

		const userInfo: OAuthUserInfo = {
			id: "gh-789",
			email: "find@example.com",
			raw: {},
		};
		const tokens: OAuthTokens = {
			accessToken: "at-xyz",
			tokenType: "Bearer",
			raw: {},
		};

		await oauth.linkAccount("user-oauth-test", "test", userInfo, tokens);

		const linked = await oauth.findLinkedUser("test", "gh-789");
		expect(linked).not.toBeNull();
		expect(linked?.userId).toBe("user-oauth-test");
	});

	it("findLinkedUser returns null when no link exists", async () => {
		const mock = createMockProvider("test");
		const oauth = createOAuthModule(db, { providers: { test: mock } });

		const result = await oauth.findLinkedUser("test", "no-such-account");
		expect(result).toBeNull();
	});

	it("linkAccount updates tokens on re-link", async () => {
		const mock = createMockProvider("test");
		const oauth = createOAuthModule(db, { providers: { test: mock } });

		const userInfo: OAuthUserInfo = { id: "relink-1", email: "relink@example.com", raw: {} };
		const firstTokens: OAuthTokens = { accessToken: "first-at", tokenType: "Bearer", raw: {} };
		const secondTokens: OAuthTokens = {
			accessToken: "second-at",
			refreshToken: "new-rt",
			tokenType: "Bearer",
			raw: {},
		};

		await oauth.linkAccount("user-oauth-test", "test", userInfo, firstTokens);
		const updated = await oauth.linkAccount("user-oauth-test", "test", userInfo, secondTokens);

		expect(updated.accessToken).toBe("second-at");
		expect(updated.refreshToken).toBe("new-rt");
	});
});
