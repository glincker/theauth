/**
 * Tests for the Dropbox OAuth provider.
 */

import { describe, expect, it } from "vitest";
import {
	createDropboxProvider,
	DEFAULT_DROPBOX_SCOPES,
	normalizeProfile as normalizeDropboxProfile,
} from "../../src/auth/oauth/providers/dropbox.js";

const CLIENT_ID = "test-dropbox-client-id";
const CLIENT_SECRET = "test-dropbox-client-secret";
const REDIRECT_URI = "https://app.example.com/callback";
const CODE_VERIFIER = "test-code-verifier-long-enough-to-be-valid-abc123";

// ---------------------------------------------------------------------------
// Canned responses
// ---------------------------------------------------------------------------

const CANNED_USER_RAW = {
	account_id: "dbid:AAH4f99T0taONIb-OurWxbNQ6ywGRopQngc",
	email: "frank@example.com",
	email_verified: true,
	name: {
		display_name: "Frank Cloudstorage",
		given_name: "Frank",
		surname: "Cloudstorage",
		abbreviated_name: "FC",
	},
	profile_photo_url: "https://dl-web.dropbox.com/account_photo/get/dbid:AAH4f99",
};

// ---------------------------------------------------------------------------
// Provider construction
// ---------------------------------------------------------------------------

describe("createDropboxProvider", () => {
	it("creates a provider with id dropbox", () => {
		const provider = createDropboxProvider({ clientId: CLIENT_ID, clientSecret: CLIENT_SECRET });
		expect(provider.id).toBe("dropbox");
		expect(provider.name).toBe("Dropbox");
	});

	it("has the correct authorization URL", () => {
		const provider = createDropboxProvider({ clientId: CLIENT_ID, clientSecret: CLIENT_SECRET });
		expect(provider.authorizationUrl).toBe("https://www.dropbox.com/oauth2/authorize");
	});

	it("has the correct token URL", () => {
		const provider = createDropboxProvider({ clientId: CLIENT_ID, clientSecret: CLIENT_SECRET });
		expect(provider.tokenUrl).toBe("https://api.dropboxapi.com/oauth2/token");
	});

	it("has the correct userinfo URL", () => {
		const provider = createDropboxProvider({ clientId: CLIENT_ID, clientSecret: CLIENT_SECRET });
		expect(provider.userInfoUrl).toBe("https://api.dropboxapi.com/2/users/get_current_account");
	});

	it("includes DEFAULT_DROPBOX_SCOPES by default", () => {
		const provider = createDropboxProvider({ clientId: CLIENT_ID, clientSecret: CLIENT_SECRET });
		for (const scope of DEFAULT_DROPBOX_SCOPES) {
			expect(provider.scopes).toContain(scope);
		}
		expect(provider.scopes).toContain("account_info.read");
	});
});

// ---------------------------------------------------------------------------
// Authorization URL
// ---------------------------------------------------------------------------

describe("createDropboxProvider — getAuthorizationUrl", () => {
	it("builds a URL with response_type=code, PKCE S256, and token_access_type=offline", async () => {
		const provider = createDropboxProvider({ clientId: CLIENT_ID, clientSecret: CLIENT_SECRET });
		const url = await provider.getAuthorizationUrl("state-abc", CODE_VERIFIER, REDIRECT_URI);
		const parsed = new URL(url);

		expect(parsed.origin + parsed.pathname).toBe("https://www.dropbox.com/oauth2/authorize");
		expect(parsed.searchParams.get("client_id")).toBe(CLIENT_ID);
		expect(parsed.searchParams.get("response_type")).toBe("code");
		expect(parsed.searchParams.get("state")).toBe("state-abc");
		expect(parsed.searchParams.get("code_challenge_method")).toBe("S256");
		expect(parsed.searchParams.get("code_challenge")).toBeTruthy();
		expect(parsed.searchParams.get("redirect_uri")).toBe(REDIRECT_URI);
		expect(parsed.searchParams.get("token_access_type")).toBe("offline");

		const scopeParam = parsed.searchParams.get("scope") ?? "";
		expect(scopeParam).toContain("account_info.read");
	});

	it("uses redirectUri override from config when provided", async () => {
		const override = "https://custom.example.com/callback";
		const provider = createDropboxProvider({
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

describe("normalizeDropboxProfile", () => {
	it("maps Dropbox user to OAuthUserInfo", () => {
		const profile = normalizeDropboxProfile(CANNED_USER_RAW as Record<string, unknown>);

		expect(profile.id).toBe("dbid:AAH4f99T0taONIb-OurWxbNQ6ywGRopQngc");
		expect(profile.email).toBe("frank@example.com");
		expect(profile.name).toBe("Frank Cloudstorage");
		expect(profile.avatar).toBe("https://dl-web.dropbox.com/account_photo/get/dbid:AAH4f99");
	});

	it("returns undefined avatar when profile_photo_url is absent", () => {
		const { profile_photo_url: _photo, ...rest } = CANNED_USER_RAW;
		const profile = normalizeDropboxProfile(rest as Record<string, unknown>);
		expect(profile.avatar).toBeUndefined();
	});

	it("throws when account_id is missing", () => {
		const { account_id: _id, ...rest } = CANNED_USER_RAW;
		expect(() => normalizeDropboxProfile(rest as Record<string, unknown>)).toThrow(
			/missing.*account_id/i,
		);
	});

	it("throws when email is missing", () => {
		const { email: _email, ...rest } = CANNED_USER_RAW;
		expect(() => normalizeDropboxProfile(rest as Record<string, unknown>)).toThrow(
			/missing.*email/i,
		);
	});
});
