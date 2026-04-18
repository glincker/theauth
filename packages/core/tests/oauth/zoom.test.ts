/**
 * Tests for the Zoom OAuth provider.
 */

import { describe, expect, it } from "vitest";
import {
	createZoomProvider,
	DEFAULT_ZOOM_SCOPES,
	normalizeProfile as normalizeZoomProfile,
} from "../../src/auth/oauth/providers/zoom.js";

const CLIENT_ID = "test-zoom-client-id";
const CLIENT_SECRET = "test-zoom-client-secret";
const REDIRECT_URI = "https://app.example.com/callback";
const CODE_VERIFIER = "test-code-verifier-long-enough-to-be-valid-abc123";

// ---------------------------------------------------------------------------
// Canned responses
// ---------------------------------------------------------------------------

const CANNED_USER_RAW = {
	id: "AbCdEfGhIjKlMnOp",
	email: "grace@example.com",
	first_name: "Grace",
	last_name: "Video",
	display_name: "Grace Video",
	pic_url: "https://lh3.googleusercontent.com/a/grace-zoom-avatar",
};

// ---------------------------------------------------------------------------
// Provider construction
// ---------------------------------------------------------------------------

describe("createZoomProvider", () => {
	it("creates a provider with id zoom", () => {
		const provider = createZoomProvider({ clientId: CLIENT_ID, clientSecret: CLIENT_SECRET });
		expect(provider.id).toBe("zoom");
		expect(provider.name).toBe("Zoom");
	});

	it("has the correct authorization URL", () => {
		const provider = createZoomProvider({ clientId: CLIENT_ID, clientSecret: CLIENT_SECRET });
		expect(provider.authorizationUrl).toBe("https://zoom.us/oauth/authorize");
	});

	it("has the correct token URL", () => {
		const provider = createZoomProvider({ clientId: CLIENT_ID, clientSecret: CLIENT_SECRET });
		expect(provider.tokenUrl).toBe("https://zoom.us/oauth/token");
	});

	it("has the correct userinfo URL", () => {
		const provider = createZoomProvider({ clientId: CLIENT_ID, clientSecret: CLIENT_SECRET });
		expect(provider.userInfoUrl).toBe("https://api.zoom.us/v2/users/me");
	});

	it("includes DEFAULT_ZOOM_SCOPES by default", () => {
		const provider = createZoomProvider({ clientId: CLIENT_ID, clientSecret: CLIENT_SECRET });
		for (const scope of DEFAULT_ZOOM_SCOPES) {
			expect(provider.scopes).toContain(scope);
		}
		expect(provider.scopes).toContain("user:read");
	});
});

// ---------------------------------------------------------------------------
// Authorization URL
// ---------------------------------------------------------------------------

describe("createZoomProvider — getAuthorizationUrl", () => {
	it("builds a URL with response_type=code and PKCE S256", async () => {
		const provider = createZoomProvider({ clientId: CLIENT_ID, clientSecret: CLIENT_SECRET });
		const url = await provider.getAuthorizationUrl("state-abc", CODE_VERIFIER, REDIRECT_URI);
		const parsed = new URL(url);

		expect(parsed.origin + parsed.pathname).toBe("https://zoom.us/oauth/authorize");
		expect(parsed.searchParams.get("client_id")).toBe(CLIENT_ID);
		expect(parsed.searchParams.get("response_type")).toBe("code");
		expect(parsed.searchParams.get("state")).toBe("state-abc");
		expect(parsed.searchParams.get("code_challenge_method")).toBe("S256");
		expect(parsed.searchParams.get("code_challenge")).toBeTruthy();
		expect(parsed.searchParams.get("redirect_uri")).toBe(REDIRECT_URI);

		const scopeParam = parsed.searchParams.get("scope") ?? "";
		expect(scopeParam).toContain("user:read");
	});

	it("uses redirectUri override from config when provided", async () => {
		const override = "https://custom.example.com/callback";
		const provider = createZoomProvider({
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

describe("normalizeZoomProfile", () => {
	it("maps Zoom user to OAuthUserInfo", () => {
		const profile = normalizeZoomProfile(CANNED_USER_RAW as Record<string, unknown>);

		expect(profile.id).toBe("AbCdEfGhIjKlMnOp");
		expect(profile.email).toBe("grace@example.com");
		expect(profile.name).toBe("Grace Video");
		expect(profile.avatar).toBe("https://lh3.googleusercontent.com/a/grace-zoom-avatar");
	});

	it("builds name from first_name + last_name when display_name is absent", () => {
		const { display_name: _display, ...rest } = CANNED_USER_RAW;
		const profile = normalizeZoomProfile(rest as Record<string, unknown>);
		expect(profile.name).toBe("Grace Video");
	});

	it("returns undefined avatar when pic_url is absent", () => {
		const { pic_url: _pic, ...rest } = CANNED_USER_RAW;
		const profile = normalizeZoomProfile(rest as Record<string, unknown>);
		expect(profile.avatar).toBeUndefined();
	});

	it("throws when id is missing", () => {
		const { id: _id, ...rest } = CANNED_USER_RAW;
		expect(() => normalizeZoomProfile(rest as Record<string, unknown>)).toThrow(/missing.*id/i);
	});

	it("throws when email is missing", () => {
		const { email: _email, ...rest } = CANNED_USER_RAW;
		expect(() => normalizeZoomProfile(rest as Record<string, unknown>)).toThrow(/missing.*email/i);
	});
});
