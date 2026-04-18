/**
 * Tests for the Spotify OAuth provider.
 */

import { describe, expect, it } from "vitest";
import {
	createSpotifyProvider,
	DEFAULT_SPOTIFY_SCOPES,
	normalizeProfile as normalizeSpotifyProfile,
} from "../../src/auth/oauth/providers/spotify.js";

const CLIENT_ID = "test-spotify-client-id";
const CLIENT_SECRET = "test-spotify-client-secret";
const REDIRECT_URI = "https://app.example.com/callback";
const CODE_VERIFIER = "test-code-verifier-long-enough-to-be-valid-abc123";

// ---------------------------------------------------------------------------
// Canned responses
// ---------------------------------------------------------------------------

const CANNED_USER_RAW = {
	id: "spotify-user-abc123",
	display_name: "Bob Listener",
	email: "bob@example.com",
	images: [
		{ url: "https://i.scdn.co/image/large.jpg", height: 300, width: 300 },
		{ url: "https://i.scdn.co/image/small.jpg", height: 64, width: 64 },
	],
};

// ---------------------------------------------------------------------------
// Provider construction
// ---------------------------------------------------------------------------

describe("createSpotifyProvider", () => {
	it("creates a provider with id spotify", () => {
		const provider = createSpotifyProvider({ clientId: CLIENT_ID, clientSecret: CLIENT_SECRET });
		expect(provider.id).toBe("spotify");
		expect(provider.name).toBe("Spotify");
	});

	it("has the correct authorization URL", () => {
		const provider = createSpotifyProvider({ clientId: CLIENT_ID, clientSecret: CLIENT_SECRET });
		expect(provider.authorizationUrl).toBe("https://accounts.spotify.com/authorize");
	});

	it("has the correct token URL", () => {
		const provider = createSpotifyProvider({ clientId: CLIENT_ID, clientSecret: CLIENT_SECRET });
		expect(provider.tokenUrl).toBe("https://accounts.spotify.com/api/token");
	});

	it("has the correct userinfo URL", () => {
		const provider = createSpotifyProvider({ clientId: CLIENT_ID, clientSecret: CLIENT_SECRET });
		expect(provider.userInfoUrl).toBe("https://api.spotify.com/v1/me");
	});

	it("includes DEFAULT_SPOTIFY_SCOPES by default", () => {
		const provider = createSpotifyProvider({ clientId: CLIENT_ID, clientSecret: CLIENT_SECRET });
		for (const scope of DEFAULT_SPOTIFY_SCOPES) {
			expect(provider.scopes).toContain(scope);
		}
	});

	it("merges extra scopes without duplicating defaults", () => {
		const provider = createSpotifyProvider({
			clientId: CLIENT_ID,
			clientSecret: CLIENT_SECRET,
			scopes: ["user-read-email", "user-top-read"],
		});
		const emailCount = provider.scopes.filter((s) => s === "user-read-email").length;
		expect(emailCount).toBe(1);
		expect(provider.scopes).toContain("user-top-read");
	});
});

// ---------------------------------------------------------------------------
// Authorization URL
// ---------------------------------------------------------------------------

describe("createSpotifyProvider — getAuthorizationUrl", () => {
	it("builds a URL with response_type=code, PKCE S256, and correct scopes", async () => {
		const provider = createSpotifyProvider({ clientId: CLIENT_ID, clientSecret: CLIENT_SECRET });
		const url = await provider.getAuthorizationUrl("state-abc", CODE_VERIFIER, REDIRECT_URI);
		const parsed = new URL(url);

		expect(parsed.origin + parsed.pathname).toBe("https://accounts.spotify.com/authorize");
		expect(parsed.searchParams.get("client_id")).toBe(CLIENT_ID);
		expect(parsed.searchParams.get("response_type")).toBe("code");
		expect(parsed.searchParams.get("state")).toBe("state-abc");
		expect(parsed.searchParams.get("code_challenge_method")).toBe("S256");
		expect(parsed.searchParams.get("code_challenge")).toBeTruthy();
		expect(parsed.searchParams.get("redirect_uri")).toBe(REDIRECT_URI);

		const scopeParam = parsed.searchParams.get("scope") ?? "";
		expect(scopeParam).toContain("user-read-email");
		expect(scopeParam).toContain("user-read-private");
	});

	it("uses redirectUri override from config when provided", async () => {
		const override = "https://custom.example.com/callback";
		const provider = createSpotifyProvider({
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

describe("normalizeSpotifyProfile", () => {
	it("maps Spotify user to OAuthUserInfo", () => {
		const profile = normalizeSpotifyProfile(CANNED_USER_RAW as Record<string, unknown>);

		expect(profile.id).toBe("spotify-user-abc123");
		expect(profile.email).toBe("bob@example.com");
		expect(profile.name).toBe("Bob Listener");
		// First image is used for avatar
		expect(profile.avatar).toBe("https://i.scdn.co/image/large.jpg");
	});

	it("returns undefined avatar when images array is empty", () => {
		const raw = { ...CANNED_USER_RAW, images: [] };
		const profile = normalizeSpotifyProfile(raw as Record<string, unknown>);
		expect(profile.avatar).toBeUndefined();
	});

	it("returns undefined avatar when images is absent", () => {
		const { images: _images, ...rest } = CANNED_USER_RAW;
		const profile = normalizeSpotifyProfile(rest as Record<string, unknown>);
		expect(profile.avatar).toBeUndefined();
	});

	it("returns undefined email when absent (e.g. Facebook-linked account)", () => {
		const { email: _email, ...rest } = CANNED_USER_RAW;
		const profile = normalizeSpotifyProfile(rest as Record<string, unknown>);
		expect(profile.email).toBeUndefined();
	});

	it("throws when id is missing", () => {
		const { id: _id, ...rest } = CANNED_USER_RAW;
		expect(() => normalizeSpotifyProfile(rest as Record<string, unknown>)).toThrow(/missing.*id/i);
	});
});
