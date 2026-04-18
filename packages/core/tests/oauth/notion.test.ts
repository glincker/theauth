/**
 * Tests for the Notion OAuth provider.
 *
 * No network calls are made. Tests validate URL construction and profile
 * normalisation against canned responses.
 */

import { describe, expect, it } from "vitest";
import {
	createNotionProvider,
	DEFAULT_NOTION_SCOPES,
	normalizeProfile as normalizeNotionProfile,
} from "../../src/auth/oauth/providers/notion.js";

const CLIENT_ID = "test-notion-client-id";
const CLIENT_SECRET = "test-notion-client-secret";
const REDIRECT_URI = "https://app.example.com/callback";
const CODE_VERIFIER = "test-code-verifier-long-enough-to-be-valid-abc123";

// ---------------------------------------------------------------------------
// Canned responses
// ---------------------------------------------------------------------------

const CANNED_TOKEN_RAW = {
	access_token: "notion-access-token",
	token_type: "bearer",
	bot_id: "bot-123",
	workspace_id: "ws-456",
	workspace_name: "My Workspace",
	owner: {
		type: "user",
		user: {
			id: "user-notion-789",
			name: "Alice Example",
			avatar_url: "https://s3.us-west-2.amazonaws.com/notion-avatars/alice.png",
			type: "person",
			person: {
				email: "alice@example.com",
			},
		},
	},
};

// ---------------------------------------------------------------------------
// Provider construction
// ---------------------------------------------------------------------------

describe("createNotionProvider", () => {
	it("creates a provider with id notion", () => {
		const provider = createNotionProvider({ clientId: CLIENT_ID, clientSecret: CLIENT_SECRET });
		expect(provider.id).toBe("notion");
		expect(provider.name).toBe("Notion");
	});

	it("has the correct authorization URL", () => {
		const provider = createNotionProvider({ clientId: CLIENT_ID, clientSecret: CLIENT_SECRET });
		expect(provider.authorizationUrl).toBe("https://api.notion.com/v1/oauth/authorize");
	});

	it("has the correct token URL", () => {
		const provider = createNotionProvider({ clientId: CLIENT_ID, clientSecret: CLIENT_SECRET });
		expect(provider.tokenUrl).toBe("https://api.notion.com/v1/oauth/token");
	});

	it("has empty scopes (Notion uses integration-level permissions)", () => {
		const provider = createNotionProvider({ clientId: CLIENT_ID, clientSecret: CLIENT_SECRET });
		expect(Array.isArray(provider.scopes)).toBe(true);
		expect(provider.scopes).toHaveLength(0);
	});

	it("DEFAULT_NOTION_SCOPES is an empty array", () => {
		expect(DEFAULT_NOTION_SCOPES).toEqual([]);
	});
});

// ---------------------------------------------------------------------------
// Authorization URL
// ---------------------------------------------------------------------------

describe("createNotionProvider — getAuthorizationUrl", () => {
	it("builds a URL with response_type=code, state, and owner=user", async () => {
		const provider = createNotionProvider({ clientId: CLIENT_ID, clientSecret: CLIENT_SECRET });
		const url = await provider.getAuthorizationUrl("state-abc", CODE_VERIFIER, REDIRECT_URI);
		const parsed = new URL(url);

		expect(parsed.origin + parsed.pathname).toBe("https://api.notion.com/v1/oauth/authorize");
		expect(parsed.searchParams.get("client_id")).toBe(CLIENT_ID);
		expect(parsed.searchParams.get("response_type")).toBe("code");
		expect(parsed.searchParams.get("state")).toBe("state-abc");
		expect(parsed.searchParams.get("owner")).toBe("user");
		expect(parsed.searchParams.get("redirect_uri")).toBe(REDIRECT_URI);
	});

	it("does not include code_challenge (Notion does not support PKCE)", async () => {
		const provider = createNotionProvider({ clientId: CLIENT_ID, clientSecret: CLIENT_SECRET });
		const url = await provider.getAuthorizationUrl("state-xyz", CODE_VERIFIER, REDIRECT_URI);
		const parsed = new URL(url);

		expect(parsed.searchParams.has("code_challenge")).toBe(false);
		expect(parsed.searchParams.has("code_challenge_method")).toBe(false);
	});

	it("uses redirectUri override from config when provided", async () => {
		const override = "https://custom.example.com/callback";
		const provider = createNotionProvider({
			clientId: CLIENT_ID,
			clientSecret: CLIENT_SECRET,
			redirectUri: override,
		});
		const url = await provider.getAuthorizationUrl("state", CODE_VERIFIER, REDIRECT_URI);
		const parsed = new URL(url);

		expect(parsed.searchParams.get("redirect_uri")).toBe(override);
	});
});

// ---------------------------------------------------------------------------
// Profile normalisation
// ---------------------------------------------------------------------------

describe("normalizeNotionProfile", () => {
	it("maps owner.user to OAuthUserInfo", () => {
		const profile = normalizeNotionProfile(CANNED_TOKEN_RAW as Record<string, unknown>);

		expect(profile.id).toBe("user-notion-789");
		expect(profile.email).toBe("alice@example.com");
		expect(profile.name).toBe("Alice Example");
		expect(profile.avatar).toBe("https://s3.us-west-2.amazonaws.com/notion-avatars/alice.png");
	});

	it("returns undefined email when person.email is absent", () => {
		const raw = {
			...CANNED_TOKEN_RAW,
			owner: {
				type: "user",
				user: {
					...CANNED_TOKEN_RAW.owner.user,
					person: {},
				},
			},
		};
		const profile = normalizeNotionProfile(raw as Record<string, unknown>);
		expect(profile.email).toBeUndefined();
	});

	it("throws when owner.user.id is missing", () => {
		const raw = {
			...CANNED_TOKEN_RAW,
			owner: { type: "workspace" },
		};
		expect(() => normalizeNotionProfile(raw as Record<string, unknown>)).toThrow(
			/missing owner\.user\.id/i,
		);
	});
});
