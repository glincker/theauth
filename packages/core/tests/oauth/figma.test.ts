/**
 * Tests for the Figma OAuth provider.
 */

import { describe, expect, it } from "vitest";
import {
	createFigmaProvider,
	DEFAULT_FIGMA_SCOPES,
	normalizeProfile as normalizeFigmaProfile,
} from "../../src/auth/oauth/providers/figma.js";

const CLIENT_ID = "test-figma-client-id";
const CLIENT_SECRET = "test-figma-client-secret";
const REDIRECT_URI = "https://app.example.com/callback";
const CODE_VERIFIER = "test-code-verifier-long-enough-to-be-valid-abc123";

// ---------------------------------------------------------------------------
// Canned responses
// ---------------------------------------------------------------------------

const CANNED_USER_RAW = {
	id: "1234567890",
	email: "eve@example.com",
	handle: "Eve Designer",
	img_url: "https://s3-alpha.figma.com/profile/eve-profile.jpg",
};

// ---------------------------------------------------------------------------
// Provider construction
// ---------------------------------------------------------------------------

describe("createFigmaProvider", () => {
	it("creates a provider with id figma", () => {
		const provider = createFigmaProvider({ clientId: CLIENT_ID, clientSecret: CLIENT_SECRET });
		expect(provider.id).toBe("figma");
		expect(provider.name).toBe("Figma");
	});

	it("has the correct authorization URL", () => {
		const provider = createFigmaProvider({ clientId: CLIENT_ID, clientSecret: CLIENT_SECRET });
		expect(provider.authorizationUrl).toBe("https://www.figma.com/oauth");
	});

	it("has the correct token URL", () => {
		const provider = createFigmaProvider({ clientId: CLIENT_ID, clientSecret: CLIENT_SECRET });
		expect(provider.tokenUrl).toBe("https://api.figma.com/v1/oauth/token");
	});

	it("has the correct userinfo URL", () => {
		const provider = createFigmaProvider({ clientId: CLIENT_ID, clientSecret: CLIENT_SECRET });
		expect(provider.userInfoUrl).toBe("https://api.figma.com/v1/me");
	});

	it("includes DEFAULT_FIGMA_SCOPES by default", () => {
		const provider = createFigmaProvider({ clientId: CLIENT_ID, clientSecret: CLIENT_SECRET });
		for (const scope of DEFAULT_FIGMA_SCOPES) {
			expect(provider.scopes).toContain(scope);
		}
		expect(provider.scopes).toContain("file_read");
	});
});

// ---------------------------------------------------------------------------
// Authorization URL
// ---------------------------------------------------------------------------

describe("createFigmaProvider — getAuthorizationUrl", () => {
	it("builds a URL with response_type=code and PKCE S256", async () => {
		const provider = createFigmaProvider({ clientId: CLIENT_ID, clientSecret: CLIENT_SECRET });
		const url = await provider.getAuthorizationUrl("state-abc", CODE_VERIFIER, REDIRECT_URI);
		const parsed = new URL(url);

		expect(parsed.origin + parsed.pathname).toBe("https://www.figma.com/oauth");
		expect(parsed.searchParams.get("client_id")).toBe(CLIENT_ID);
		expect(parsed.searchParams.get("response_type")).toBe("code");
		expect(parsed.searchParams.get("state")).toBe("state-abc");
		expect(parsed.searchParams.get("code_challenge_method")).toBe("S256");
		expect(parsed.searchParams.get("code_challenge")).toBeTruthy();
		expect(parsed.searchParams.get("redirect_uri")).toBe(REDIRECT_URI);

		const scopeParam = parsed.searchParams.get("scope") ?? "";
		expect(scopeParam).toContain("file_read");
	});

	it("uses redirectUri override from config when provided", async () => {
		const override = "https://custom.example.com/callback";
		const provider = createFigmaProvider({
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

describe("normalizeFigmaProfile", () => {
	it("maps Figma user to OAuthUserInfo", () => {
		const profile = normalizeFigmaProfile(CANNED_USER_RAW as Record<string, unknown>);

		expect(profile.id).toBe("1234567890");
		expect(profile.email).toBe("eve@example.com");
		expect(profile.name).toBe("Eve Designer");
		expect(profile.avatar).toBe("https://s3-alpha.figma.com/profile/eve-profile.jpg");
	});

	it("returns undefined avatar when img_url is absent", () => {
		const { img_url: _img, ...rest } = CANNED_USER_RAW;
		const profile = normalizeFigmaProfile(rest as Record<string, unknown>);
		expect(profile.avatar).toBeUndefined();
	});

	it("throws when id is missing", () => {
		const { id: _id, ...rest } = CANNED_USER_RAW;
		expect(() => normalizeFigmaProfile(rest as Record<string, unknown>)).toThrow(/missing.*id/i);
	});

	it("throws when email is missing", () => {
		const { email: _email, ...rest } = CANNED_USER_RAW;
		expect(() => normalizeFigmaProfile(rest as Record<string, unknown>)).toThrow(/missing.*email/i);
	});
});
