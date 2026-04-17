/**
 * Tests for the Discord OAuth provider.
 */

import { describe, expect, it } from "vitest";
import {
	createDiscordProvider,
	DEFAULT_DISCORD_SCOPES,
	normalizeProfile as normalizeDiscordProfile,
} from "../../src/auth/oauth/providers/discord.js";

const CLIENT_ID = "test-discord-client-id";
const CLIENT_SECRET = "test-discord-client-secret";
const REDIRECT_URI = "https://app.example.com/callback";
const CODE_VERIFIER = "test-code-verifier-long-enough-to-be-valid-abc123";

// ---------------------------------------------------------------------------
// Canned responses
// ---------------------------------------------------------------------------

const CANNED_USER_RAW = {
	id: "123456789012345678",
	username: "alice",
	global_name: "Alice Example",
	email: "alice@example.com",
	verified: true,
	avatar: "a_1234abcd5678efgh",
};

// ---------------------------------------------------------------------------
// Provider construction
// ---------------------------------------------------------------------------

describe("createDiscordProvider", () => {
	it("creates a provider with id discord", () => {
		const provider = createDiscordProvider({ clientId: CLIENT_ID, clientSecret: CLIENT_SECRET });
		expect(provider.id).toBe("discord");
		expect(provider.name).toBe("Discord");
	});

	it("has the correct authorization URL", () => {
		const provider = createDiscordProvider({ clientId: CLIENT_ID, clientSecret: CLIENT_SECRET });
		expect(provider.authorizationUrl).toBe("https://discord.com/api/oauth2/authorize");
	});

	it("has the correct token URL", () => {
		const provider = createDiscordProvider({ clientId: CLIENT_ID, clientSecret: CLIENT_SECRET });
		expect(provider.tokenUrl).toBe("https://discord.com/api/oauth2/token");
	});

	it("has the correct userinfo URL", () => {
		const provider = createDiscordProvider({ clientId: CLIENT_ID, clientSecret: CLIENT_SECRET });
		expect(provider.userInfoUrl).toBe("https://discord.com/api/users/@me");
	});

	it("includes DEFAULT_DISCORD_SCOPES by default", () => {
		const provider = createDiscordProvider({ clientId: CLIENT_ID, clientSecret: CLIENT_SECRET });
		for (const scope of DEFAULT_DISCORD_SCOPES) {
			expect(provider.scopes).toContain(scope);
		}
	});
});

// ---------------------------------------------------------------------------
// Authorization URL
// ---------------------------------------------------------------------------

describe("createDiscordProvider — getAuthorizationUrl", () => {
	it("builds a URL with response_type=code and PKCE S256", async () => {
		const provider = createDiscordProvider({ clientId: CLIENT_ID, clientSecret: CLIENT_SECRET });
		const url = await provider.getAuthorizationUrl("state-abc", CODE_VERIFIER, REDIRECT_URI);
		const parsed = new URL(url);

		expect(parsed.origin + parsed.pathname).toBe("https://discord.com/api/oauth2/authorize");
		expect(parsed.searchParams.get("client_id")).toBe(CLIENT_ID);
		expect(parsed.searchParams.get("response_type")).toBe("code");
		expect(parsed.searchParams.get("state")).toBe("state-abc");
		expect(parsed.searchParams.get("code_challenge_method")).toBe("S256");
		expect(parsed.searchParams.get("code_challenge")).toBeTruthy();
		expect(parsed.searchParams.get("redirect_uri")).toBe(REDIRECT_URI);

		const scopeParam = parsed.searchParams.get("scope") ?? "";
		expect(scopeParam).toContain("identify");
		expect(scopeParam).toContain("email");
	});

	it("uses redirectUri override from config when provided", async () => {
		const override = "https://custom.example.com/callback";
		const provider = createDiscordProvider({
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

describe("normalizeDiscordProfile", () => {
	it("maps Discord user to OAuthUserInfo with CDN avatar URL", () => {
		const profile = normalizeDiscordProfile(CANNED_USER_RAW as Record<string, unknown>);

		expect(profile.id).toBe("123456789012345678");
		expect(profile.email).toBe("alice@example.com");
		expect(profile.name).toBe("Alice Example");
		// Animated avatar hash starts with a_, format should be .gif
		expect(profile.avatar).toContain("cdn.discordapp.com");
		expect(profile.avatar).toContain("123456789012345678");
		expect(profile.avatar).toContain("a_1234abcd5678efgh");
	});

	it("uses global_name over legacy username#discriminator", () => {
		const raw = {
			...CANNED_USER_RAW,
			username: "legacyname",
			discriminator: "1234",
			global_name: "Modern Name",
		};
		const profile = normalizeDiscordProfile(raw as Record<string, unknown>);
		expect(profile.name).toBe("Modern Name");
	});

	it("falls back to username#discriminator when global_name is null", () => {
		const raw = {
			...CANNED_USER_RAW,
			username: "olduser",
			discriminator: "9999",
			global_name: null,
		};
		const profile = normalizeDiscordProfile(raw as Record<string, unknown>);
		expect(profile.name).toBe("olduser#9999");
	});

	it("returns undefined avatar when avatar hash is null", () => {
		const raw = { ...CANNED_USER_RAW, avatar: null };
		const profile = normalizeDiscordProfile(raw as Record<string, unknown>);
		expect(profile.avatar).toBeUndefined();
	});

	it("throws when id is missing", () => {
		const { id: _id, ...rest } = CANNED_USER_RAW;
		expect(() => normalizeDiscordProfile(rest as Record<string, unknown>)).toThrow(/missing.*id/i);
	});

	it("throws when email is missing", () => {
		const { email: _email, ...rest } = CANNED_USER_RAW;
		expect(() => normalizeDiscordProfile(rest as Record<string, unknown>)).toThrow(/no email/i);
	});
});
