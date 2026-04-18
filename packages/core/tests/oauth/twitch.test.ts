/**
 * Tests for the Twitch OAuth provider.
 */

import { describe, expect, it } from "vitest";
import {
	createTwitchProvider,
	DEFAULT_TWITCH_SCOPES,
	normalizeProfile as normalizeTwitchProfile,
} from "../../src/auth/oauth/providers/twitch.js";

const CLIENT_ID = "test-twitch-client-id";
const CLIENT_SECRET = "test-twitch-client-secret";
const REDIRECT_URI = "https://app.example.com/callback";
const CODE_VERIFIER = "test-code-verifier-long-enough-to-be-valid-abc123";

// ---------------------------------------------------------------------------
// Canned responses
// ---------------------------------------------------------------------------

const CANNED_USER_RAW = {
	data: [
		{
			id: "12345678",
			login: "streamerdan",
			display_name: "StreamerDan",
			email: "dan@example.com",
			profile_image_url: "https://static-cdn.jtvnw.net/jtv_user_pictures/dan-profile.png",
		},
	],
};

// ---------------------------------------------------------------------------
// Provider construction
// ---------------------------------------------------------------------------

describe("createTwitchProvider", () => {
	it("creates a provider with id twitch", () => {
		const provider = createTwitchProvider({ clientId: CLIENT_ID, clientSecret: CLIENT_SECRET });
		expect(provider.id).toBe("twitch");
		expect(provider.name).toBe("Twitch");
	});

	it("has the correct authorization URL", () => {
		const provider = createTwitchProvider({ clientId: CLIENT_ID, clientSecret: CLIENT_SECRET });
		expect(provider.authorizationUrl).toBe("https://id.twitch.tv/oauth2/authorize");
	});

	it("has the correct token URL", () => {
		const provider = createTwitchProvider({ clientId: CLIENT_ID, clientSecret: CLIENT_SECRET });
		expect(provider.tokenUrl).toBe("https://id.twitch.tv/oauth2/token");
	});

	it("has the correct userinfo URL", () => {
		const provider = createTwitchProvider({ clientId: CLIENT_ID, clientSecret: CLIENT_SECRET });
		expect(provider.userInfoUrl).toBe("https://api.twitch.tv/helix/users");
	});

	it("includes DEFAULT_TWITCH_SCOPES by default", () => {
		const provider = createTwitchProvider({ clientId: CLIENT_ID, clientSecret: CLIENT_SECRET });
		for (const scope of DEFAULT_TWITCH_SCOPES) {
			expect(provider.scopes).toContain(scope);
		}
	});
});

// ---------------------------------------------------------------------------
// Authorization URL
// ---------------------------------------------------------------------------

describe("createTwitchProvider — getAuthorizationUrl", () => {
	it("builds a URL with response_type=code and PKCE S256", async () => {
		const provider = createTwitchProvider({ clientId: CLIENT_ID, clientSecret: CLIENT_SECRET });
		const url = await provider.getAuthorizationUrl("state-abc", CODE_VERIFIER, REDIRECT_URI);
		const parsed = new URL(url);

		expect(parsed.origin + parsed.pathname).toBe("https://id.twitch.tv/oauth2/authorize");
		expect(parsed.searchParams.get("client_id")).toBe(CLIENT_ID);
		expect(parsed.searchParams.get("response_type")).toBe("code");
		expect(parsed.searchParams.get("state")).toBe("state-abc");
		expect(parsed.searchParams.get("code_challenge_method")).toBe("S256");
		expect(parsed.searchParams.get("code_challenge")).toBeTruthy();
		expect(parsed.searchParams.get("redirect_uri")).toBe(REDIRECT_URI);

		const scopeParam = parsed.searchParams.get("scope") ?? "";
		expect(scopeParam).toContain("user:read:email");
	});

	it("uses redirectUri override from config when provided", async () => {
		const override = "https://custom.example.com/callback";
		const provider = createTwitchProvider({
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

describe("normalizeTwitchProfile", () => {
	it("maps Twitch helix user to OAuthUserInfo", () => {
		const profile = normalizeTwitchProfile(CANNED_USER_RAW as Record<string, unknown>);

		expect(profile.id).toBe("12345678");
		expect(profile.email).toBe("dan@example.com");
		expect(profile.name).toBe("StreamerDan");
		expect(profile.avatar).toBe("https://static-cdn.jtvnw.net/jtv_user_pictures/dan-profile.png");
	});

	it("throws when data array is empty", () => {
		const raw = { data: [] };
		expect(() => normalizeTwitchProfile(raw as Record<string, unknown>)).toThrow(/missing.*id/i);
	});

	it("throws when email is absent (scope not granted)", () => {
		const raw = {
			data: [{ ...CANNED_USER_RAW.data[0], email: undefined }],
		};
		expect(() => normalizeTwitchProfile(raw as Record<string, unknown>)).toThrow(/no email/i);
	});
});
