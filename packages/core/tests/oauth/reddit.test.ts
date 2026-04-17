/**
 * Tests for the Reddit OAuth provider.
 */

import { describe, expect, it } from "vitest";
import {
	createRedditProvider,
	DEFAULT_REDDIT_SCOPES,
	normalizeProfile as normalizeRedditProfile,
} from "../../src/auth/oauth/providers/reddit.js";

const CLIENT_ID = "test-reddit-client-id";
const CLIENT_SECRET = "test-reddit-client-secret";
const REDIRECT_URI = "https://app.example.com/callback";
const CODE_VERIFIER = "test-code-verifier-long-enough-to-be-valid-abc123";

// ---------------------------------------------------------------------------
// Canned responses
// ---------------------------------------------------------------------------

const CANNED_USER_RAW = {
	id: "abc123",
	name: "redditor42",
	icon_img: "https://www.redditstatic.com/avatars/defaults/v2/avatar_default_1.png?token=xyz",
};

// ---------------------------------------------------------------------------
// Provider construction
// ---------------------------------------------------------------------------

describe("createRedditProvider", () => {
	it("creates a provider with id reddit", () => {
		const provider = createRedditProvider({ clientId: CLIENT_ID, clientSecret: CLIENT_SECRET });
		expect(provider.id).toBe("reddit");
		expect(provider.name).toBe("Reddit");
	});

	it("has the correct authorization URL", () => {
		const provider = createRedditProvider({ clientId: CLIENT_ID, clientSecret: CLIENT_SECRET });
		expect(provider.authorizationUrl).toBe("https://www.reddit.com/api/v1/authorize");
	});

	it("has the correct token URL", () => {
		const provider = createRedditProvider({ clientId: CLIENT_ID, clientSecret: CLIENT_SECRET });
		expect(provider.tokenUrl).toBe("https://www.reddit.com/api/v1/access_token");
	});

	it("has the correct userinfo URL", () => {
		const provider = createRedditProvider({ clientId: CLIENT_ID, clientSecret: CLIENT_SECRET });
		expect(provider.userInfoUrl).toBe("https://oauth.reddit.com/api/v1/me");
	});

	it("includes DEFAULT_REDDIT_SCOPES by default", () => {
		const provider = createRedditProvider({ clientId: CLIENT_ID, clientSecret: CLIENT_SECRET });
		for (const scope of DEFAULT_REDDIT_SCOPES) {
			expect(provider.scopes).toContain(scope);
		}
	});
});

// ---------------------------------------------------------------------------
// Authorization URL
// ---------------------------------------------------------------------------

describe("createRedditProvider — getAuthorizationUrl", () => {
	it("builds a URL with response_type=code, PKCE S256, and duration=permanent", async () => {
		const provider = createRedditProvider({ clientId: CLIENT_ID, clientSecret: CLIENT_SECRET });
		const url = await provider.getAuthorizationUrl("state-abc", CODE_VERIFIER, REDIRECT_URI);
		const parsed = new URL(url);

		expect(parsed.origin + parsed.pathname).toBe("https://www.reddit.com/api/v1/authorize");
		expect(parsed.searchParams.get("client_id")).toBe(CLIENT_ID);
		expect(parsed.searchParams.get("response_type")).toBe("code");
		expect(parsed.searchParams.get("state")).toBe("state-abc");
		expect(parsed.searchParams.get("code_challenge_method")).toBe("S256");
		expect(parsed.searchParams.get("code_challenge")).toBeTruthy();
		expect(parsed.searchParams.get("redirect_uri")).toBe(REDIRECT_URI);
		// Reddit requires duration=permanent for refresh tokens
		expect(parsed.searchParams.get("duration")).toBe("permanent");

		const scopeParam = parsed.searchParams.get("scope") ?? "";
		expect(scopeParam).toContain("identity");
	});

	it("uses redirectUri override from config when provided", async () => {
		const override = "https://custom.example.com/callback";
		const provider = createRedditProvider({
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

describe("normalizeRedditProfile", () => {
	it("maps Reddit user to OAuthUserInfo with no email", () => {
		const profile = normalizeRedditProfile(CANNED_USER_RAW as Record<string, unknown>);

		expect(profile.id).toBe("abc123");
		expect(profile.name).toBe("redditor42");
		// Reddit does not expose email
		expect(profile.email).toBeUndefined();
	});

	it("strips query params from icon_img URL", () => {
		const profile = normalizeRedditProfile(CANNED_USER_RAW as Record<string, unknown>);
		expect(profile.avatar).toBe(
			"https://www.redditstatic.com/avatars/defaults/v2/avatar_default_1.png",
		);
		expect(profile.avatar).not.toContain("?");
	});

	it("returns undefined avatar when icon_img is absent", () => {
		const { icon_img: _img, ...rest } = CANNED_USER_RAW;
		const profile = normalizeRedditProfile(rest as Record<string, unknown>);
		expect(profile.avatar).toBeUndefined();
	});

	it("throws when id is missing", () => {
		const { id: _id, ...rest } = CANNED_USER_RAW;
		expect(() => normalizeRedditProfile(rest as Record<string, unknown>)).toThrow(/missing.*id/i);
	});

	it("throws when name is missing", () => {
		const { name: _name, ...rest } = CANNED_USER_RAW;
		expect(() => normalizeRedditProfile(rest as Record<string, unknown>)).toThrow(/missing.*name/i);
	});
});
