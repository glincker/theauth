/**
 * Tests for the Atlassian OAuth provider.
 */

import { describe, expect, it } from "vitest";
import {
	createAtlassianProvider,
	DEFAULT_ATLASSIAN_SCOPES,
	normalizeProfile as normalizeAtlassianProfile,
} from "../../src/auth/oauth/providers/atlassian.js";

const CLIENT_ID = "test-atlassian-client-id";
const CLIENT_SECRET = "test-atlassian-client-secret";
const REDIRECT_URI = "https://app.example.com/callback";
const CODE_VERIFIER = "test-code-verifier-long-enough-to-be-valid-abc123";

// ---------------------------------------------------------------------------
// Canned responses
// ---------------------------------------------------------------------------

const CANNED_USER_RAW = {
	account_id: "557058:f58131cb-b67d-43c7-b475-1234abcd5678",
	email: "henry@example.com",
	name: "Henry Jira",
	picture: "https://secure.gravatar.com/avatar/henry-hash?d=identicon&s=48",
	account_type: "atlassian",
};

// ---------------------------------------------------------------------------
// Provider construction
// ---------------------------------------------------------------------------

describe("createAtlassianProvider", () => {
	it("creates a provider with id atlassian", () => {
		const provider = createAtlassianProvider({ clientId: CLIENT_ID, clientSecret: CLIENT_SECRET });
		expect(provider.id).toBe("atlassian");
		expect(provider.name).toBe("Atlassian");
	});

	it("has the correct authorization URL", () => {
		const provider = createAtlassianProvider({ clientId: CLIENT_ID, clientSecret: CLIENT_SECRET });
		expect(provider.authorizationUrl).toBe("https://auth.atlassian.com/authorize");
	});

	it("has the correct token URL", () => {
		const provider = createAtlassianProvider({ clientId: CLIENT_ID, clientSecret: CLIENT_SECRET });
		expect(provider.tokenUrl).toBe("https://auth.atlassian.com/oauth/token");
	});

	it("has the correct userinfo URL", () => {
		const provider = createAtlassianProvider({ clientId: CLIENT_ID, clientSecret: CLIENT_SECRET });
		expect(provider.userInfoUrl).toBe("https://api.atlassian.com/me");
	});

	it("includes DEFAULT_ATLASSIAN_SCOPES by default", () => {
		const provider = createAtlassianProvider({ clientId: CLIENT_ID, clientSecret: CLIENT_SECRET });
		for (const scope of DEFAULT_ATLASSIAN_SCOPES) {
			expect(provider.scopes).toContain(scope);
		}
		expect(provider.scopes).toContain("read:me");
	});
});

// ---------------------------------------------------------------------------
// Authorization URL
// ---------------------------------------------------------------------------

describe("createAtlassianProvider — getAuthorizationUrl", () => {
	it("builds a URL with response_type=code, PKCE S256, and audience=api.atlassian.com", async () => {
		const provider = createAtlassianProvider({ clientId: CLIENT_ID, clientSecret: CLIENT_SECRET });
		const url = await provider.getAuthorizationUrl("state-abc", CODE_VERIFIER, REDIRECT_URI);
		const parsed = new URL(url);

		expect(parsed.origin + parsed.pathname).toBe("https://auth.atlassian.com/authorize");
		expect(parsed.searchParams.get("client_id")).toBe(CLIENT_ID);
		expect(parsed.searchParams.get("response_type")).toBe("code");
		expect(parsed.searchParams.get("state")).toBe("state-abc");
		expect(parsed.searchParams.get("code_challenge_method")).toBe("S256");
		expect(parsed.searchParams.get("code_challenge")).toBeTruthy();
		expect(parsed.searchParams.get("redirect_uri")).toBe(REDIRECT_URI);
		// Required by Atlassian to scope the token to their API
		expect(parsed.searchParams.get("audience")).toBe("api.atlassian.com");
		expect(parsed.searchParams.get("prompt")).toBe("consent");

		const scopeParam = parsed.searchParams.get("scope") ?? "";
		expect(scopeParam).toContain("read:me");
	});

	it("uses redirectUri override from config when provided", async () => {
		const override = "https://custom.example.com/callback";
		const provider = createAtlassianProvider({
			clientId: CLIENT_ID,
			clientSecret: CLIENT_SECRET,
			redirectUri: override,
		});
		const url = await provider.getAuthorizationUrl("state", CODE_VERIFIER, REDIRECT_URI);
		expect(new URL(url).searchParams.get("redirect_uri")).toBe(override);
	});
});

// ---------------------------------------------------------------------------
// Profile normalisation
// ---------------------------------------------------------------------------

describe("normalizeAtlassianProfile", () => {
	it("maps Atlassian user to OAuthUserInfo", () => {
		const profile = normalizeAtlassianProfile(CANNED_USER_RAW as Record<string, unknown>);

		expect(profile.id).toBe("557058:f58131cb-b67d-43c7-b475-1234abcd5678");
		expect(profile.email).toBe("henry@example.com");
		expect(profile.name).toBe("Henry Jira");
		expect(profile.avatar).toBe("https://secure.gravatar.com/avatar/henry-hash?d=identicon&s=48");
	});

	it("returns undefined email when absent", () => {
		const { email: _email, ...rest } = CANNED_USER_RAW;
		const profile = normalizeAtlassianProfile(rest as Record<string, unknown>);
		expect(profile.email).toBeUndefined();
	});

	it("returns undefined avatar when picture is absent", () => {
		const { picture: _pic, ...rest } = CANNED_USER_RAW;
		const profile = normalizeAtlassianProfile(rest as Record<string, unknown>);
		expect(profile.avatar).toBeUndefined();
	});

	it("throws when account_id is missing", () => {
		const { account_id: _id, ...rest } = CANNED_USER_RAW;
		expect(() => normalizeAtlassianProfile(rest as Record<string, unknown>)).toThrow(
			/missing.*account_id/i,
		);
	});
});
