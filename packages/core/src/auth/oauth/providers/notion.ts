/**
 * Notion OAuth 2.0 provider.
 *
 * Endpoints:
 * - Authorization: https://api.notion.com/v1/oauth/authorize
 * - Token:         https://api.notion.com/v1/oauth/token
 * - UserInfo:      embedded in the token response (`owner` field)
 *
 * Notes:
 * - Notion does not have a separate UserInfo endpoint. User identity is
 *   returned as part of the token exchange response inside `owner.user`.
 *   The provider captures the token response in a closure so that
 *   `getUserInfo` can extract it without a redundant network call.
 * - The token endpoint uses HTTP Basic auth (client_id:client_secret).
 * - All Notion API requests require the `Notion-Version` header.
 * - Notion uses integration-level permissions rather than OAuth scopes.
 *   Workspaces a user authorizes appear in `workspace_id` / `workspace_name`
 *   in the token response.
 * - The `owner.user.person.email` field is present only when the integration
 *   is authorized by a person (not a bot). For bot authorizations
 *   `owner.type` is `"workspace"` and `email` may be absent.
 * - PKCE is not documented by Notion; the code_challenge is omitted for
 *   compatibility with their authorization server.
 *
 * Docs: https://developers.notion.com/docs/authorization
 */

import type { OAuthProvider, OAuthProviderConfig, OAuthTokens, OAuthUserInfo } from "../types.js";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const AUTHORIZATION_URL = "https://api.notion.com/v1/oauth/authorize";
const TOKEN_URL = "https://api.notion.com/v1/oauth/token";
const NOTION_VERSION = "2022-06-28";

// Notion does not use scopes in the traditional OAuth sense; permissions are
// managed at the integration level in the Notion workspace settings.
export const DEFAULT_NOTION_SCOPES: string[] = [];

// ---------------------------------------------------------------------------
// Raw response shapes
// ---------------------------------------------------------------------------

interface NotionTokenResponse {
	access_token: string;
	token_type: string;
	bot_id: string;
	workspace_id: string;
	workspace_name?: string;
	workspace_icon?: string;
	owner: NotionOwner;
	duplicated_template_id?: string | null;
}

interface NotionOwner {
	type: "user" | "workspace";
	user?: NotionUser;
}

interface NotionUser {
	id: string;
	name?: string;
	avatar_url?: string | null;
	type?: "person" | "bot";
	person?: {
		email?: string;
	};
}

// ---------------------------------------------------------------------------
// Profile normalisation
// ---------------------------------------------------------------------------

export function normalizeProfile(raw: Record<string, unknown>): OAuthUserInfo {
	const tokenData = raw as unknown as NotionTokenResponse;
	const user = tokenData?.owner?.user;

	if (!user?.id) {
		throw new Error(
			"Notion token response missing owner.user.id. " +
				"Ensure the integration is authorized by a person, not a workspace bot.",
		);
	}

	return {
		id: user.id,
		email: user.person?.email,
		name: user.name,
		avatar: user.avatar_url ?? undefined,
		raw,
	};
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/**
 * Create a Notion OAuth provider instance.
 *
 * @example
 * ```typescript
 * const notion = createNotionProvider({
 *   clientId: process.env.NOTION_CLIENT_ID,
 *   clientSecret: process.env.NOTION_CLIENT_SECRET,
 * });
 * ```
 */
export function createNotionProvider(config: OAuthProviderConfig): OAuthProvider {
	// Notion does not use scopes in the traditional sense; permissions are
	// managed at the integration level in the Notion UI.
	const scopes: string[] = [];

	// Notion embeds user info in the token response. We cache the last raw
	// token payload in this closure so getUserInfo can read it without a
	// separate network call (there is no /me endpoint).
	let lastTokenRaw: Record<string, unknown> | null = null;

	async function getAuthorizationUrl(
		state: string,
		_codeVerifier: string,
		redirectUri: string,
	): Promise<string> {
		const effectiveRedirectUri = config.redirectUri ?? redirectUri;

		const params = new URLSearchParams({
			client_id: config.clientId,
			redirect_uri: effectiveRedirectUri,
			response_type: "code",
			owner: "user",
			state,
		});

		return `${AUTHORIZATION_URL}?${params.toString()}`;
	}

	async function exchangeCode(
		code: string,
		_codeVerifier: string,
		redirectUri: string,
	): Promise<OAuthTokens> {
		const effectiveRedirectUri = config.redirectUri ?? redirectUri;

		// Notion's token endpoint uses HTTP Basic auth.
		const credentials = btoa(`${config.clientId}:${config.clientSecret}`);

		const response = await fetch(TOKEN_URL, {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				Authorization: `Basic ${credentials}`,
				"Notion-Version": NOTION_VERSION,
			},
			body: JSON.stringify({
				grant_type: "authorization_code",
				code,
				redirect_uri: effectiveRedirectUri,
			}),
		});

		if (!response.ok) {
			const text = await response.text();
			throw new Error(`Notion token exchange failed (${response.status}): ${text}`);
		}

		const raw = (await response.json()) as Record<string, unknown>;
		const data = raw as unknown as NotionTokenResponse;

		// Cache the raw payload for use in getUserInfo.
		lastTokenRaw = raw;

		return {
			accessToken: data.access_token,
			tokenType: data.token_type ?? "Bearer",
			raw,
		};
	}

	async function getUserInfo(_accessToken: string): Promise<OAuthUserInfo> {
		// Notion embeds user identity in the token response. getUserInfo is called
		// immediately after exchangeCode so the cached payload is always fresh.
		if (!lastTokenRaw) {
			throw new Error(
				"Notion getUserInfo called before exchangeCode. " +
					"Call exchangeCode first to obtain the token response.",
			);
		}

		const tokenData = lastTokenRaw as unknown as NotionTokenResponse;
		const user = tokenData?.owner?.user;

		if (!user?.id) {
			throw new Error(
				"Notion token response missing owner.user.id. " +
					"Ensure the integration is authorized by a person, not a workspace bot.",
			);
		}

		const email = user.person?.email;
		const avatar = user.avatar_url ?? undefined;

		return {
			id: user.id,
			email,
			name: user.name,
			avatar,
			raw: lastTokenRaw,
		};
	}

	return {
		id: "notion",
		name: "Notion",
		authorizationUrl: AUTHORIZATION_URL,
		tokenUrl: TOKEN_URL,
		// No separate UserInfo URL; identity comes from the token response.
		userInfoUrl: undefined,
		scopes,
		getAuthorizationUrl,
		exchangeCode,
		getUserInfo,
	};
}
