/**
 * Tests for the Slack OAuth / OIDC provider.
 */

import { describe, expect, it } from "vitest";
import {
	createSlackProvider,
	DEFAULT_SLACK_SCOPES,
	normalizeProfile as normalizeSlackProfile,
} from "../../src/auth/oauth/providers/slack.js";

const CLIENT_ID = "test-slack-client-id";
const CLIENT_SECRET = "test-slack-client-secret";
const REDIRECT_URI = "https://app.example.com/callback";
const CODE_VERIFIER = "test-code-verifier-long-enough-to-be-valid-abc123";

// ---------------------------------------------------------------------------
// Canned responses
// ---------------------------------------------------------------------------

const CANNED_USERINFO_RAW = {
	ok: true,
	sub: "U01ABC123DE",
	email: "carol@example.com",
	name: "Carol Example",
	picture: "https://avatars.slack-edge.com/carol.jpg",
	"https://slack.com/user_id": "U01ABC123DE",
};

// ---------------------------------------------------------------------------
// Provider construction
// ---------------------------------------------------------------------------

describe("createSlackProvider", () => {
	it("creates a provider with id slack", () => {
		const provider = createSlackProvider({ clientId: CLIENT_ID, clientSecret: CLIENT_SECRET });
		expect(provider.id).toBe("slack");
		expect(provider.name).toBe("Slack");
	});

	it("has the correct authorization URL", () => {
		const provider = createSlackProvider({ clientId: CLIENT_ID, clientSecret: CLIENT_SECRET });
		expect(provider.authorizationUrl).toBe("https://slack.com/oauth/v2/authorize");
	});

	it("has the correct token URL", () => {
		const provider = createSlackProvider({ clientId: CLIENT_ID, clientSecret: CLIENT_SECRET });
		expect(provider.tokenUrl).toBe("https://slack.com/api/oauth.v2.access");
	});

	it("has the correct userinfo URL", () => {
		const provider = createSlackProvider({ clientId: CLIENT_ID, clientSecret: CLIENT_SECRET });
		expect(provider.userInfoUrl).toBe("https://slack.com/api/openid.connect.userInfo");
	});

	it("includes DEFAULT_SLACK_SCOPES by default", () => {
		const provider = createSlackProvider({ clientId: CLIENT_ID, clientSecret: CLIENT_SECRET });
		for (const scope of DEFAULT_SLACK_SCOPES) {
			expect(provider.scopes).toContain(scope);
		}
	});
});

// ---------------------------------------------------------------------------
// Authorization URL
// ---------------------------------------------------------------------------

describe("createSlackProvider — getAuthorizationUrl", () => {
	it("builds a URL with response_type=code and openid scopes", async () => {
		const provider = createSlackProvider({ clientId: CLIENT_ID, clientSecret: CLIENT_SECRET });
		const url = await provider.getAuthorizationUrl("state-abc", CODE_VERIFIER, REDIRECT_URI);
		const parsed = new URL(url);

		expect(parsed.origin + parsed.pathname).toBe("https://slack.com/oauth/v2/authorize");
		expect(parsed.searchParams.get("client_id")).toBe(CLIENT_ID);
		expect(parsed.searchParams.get("response_type")).toBe("code");
		expect(parsed.searchParams.get("state")).toBe("state-abc");
		expect(parsed.searchParams.get("redirect_uri")).toBe(REDIRECT_URI);

		const scopeParam = parsed.searchParams.get("scope") ?? "";
		expect(scopeParam).toContain("openid");
		expect(scopeParam).toContain("profile");
		expect(scopeParam).toContain("email");
	});

	it("uses redirectUri override from config when provided", async () => {
		const override = "https://custom.example.com/callback";
		const provider = createSlackProvider({
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

describe("normalizeSlackProfile", () => {
	it("maps Slack OIDC userinfo to OAuthUserInfo", () => {
		const profile = normalizeSlackProfile(CANNED_USERINFO_RAW as Record<string, unknown>);

		expect(profile.id).toBe("U01ABC123DE");
		expect(profile.email).toBe("carol@example.com");
		expect(profile.name).toBe("Carol Example");
		expect(profile.avatar).toBe("https://avatars.slack-edge.com/carol.jpg");
	});

	it("falls back to user_id claim when sub is absent", () => {
		const { sub: _sub, ...rest } = CANNED_USERINFO_RAW;
		const profile = normalizeSlackProfile(rest as Record<string, unknown>);
		expect(profile.id).toBe("U01ABC123DE");
	});

	it("throws when both sub and user_id are absent", () => {
		const { "https://slack.com/user_id": _userId, ...raw } = CANNED_USERINFO_RAW;
		const withoutUserId: Record<string, unknown> = { ...raw, sub: undefined };
		expect(() => normalizeSlackProfile(withoutUserId)).toThrow(/missing.*sub/i);
	});

	it("throws when email is absent", () => {
		const { email: _email, ...rest } = CANNED_USERINFO_RAW;
		expect(() => normalizeSlackProfile(rest as Record<string, unknown>)).toThrow(/no email/i);
	});

	it("throws when ok is false", () => {
		const raw = { ...CANNED_USERINFO_RAW, ok: false, error: "token_revoked" };
		expect(() => normalizeSlackProfile(raw as Record<string, unknown>)).toThrow(/token_revoked/i);
	});
});
