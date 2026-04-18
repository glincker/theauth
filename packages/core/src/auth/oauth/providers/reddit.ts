/**
 * Reddit OAuth 2.0 provider.
 *
 * Endpoints:
 * - Authorization: https://www.reddit.com/api/v1/authorize
 * - Token:         https://www.reddit.com/api/v1/access_token
 * - UserInfo:      https://oauth.reddit.com/api/v1/me
 *
 * Notes:
 * - Reddit's token endpoint uses HTTP Basic authentication (client_id as the
 *   username, client_secret as the password) rather than posting credentials
 *   in the request body.
 * - The `identity` scope grants access to the user's Reddit account info.
 * - Reddit does not expose the user's email address via OAuth; the `name`
 *   field (Reddit username) is the stable identifier.
 * - The UserInfo endpoint requires a descriptive `User-Agent` header. Reddit
 *   blocks requests with generic agents (e.g., "python-requests"). Format:
 *   `platform:app_id:version (by /u/username)`.
 * - Avatar URLs (`icon_img`) include query parameters; strip them when storing
 *   to avoid caching issues.
 * - PKCE is supported but Reddit also accepts flows without it for server-side
 *   apps; KavachOS uses PKCE S256 consistently.
 *
 * Docs: https://www.reddit.com/dev/api/oauth
 */

import { deriveCodeChallenge } from "../pkce.js";
import type { OAuthProvider, OAuthProviderConfig, OAuthTokens, OAuthUserInfo } from "../types.js";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const AUTHORIZATION_URL = "https://www.reddit.com/api/v1/authorize";
const TOKEN_URL = "https://www.reddit.com/api/v1/access_token";
const USER_INFO_URL = "https://oauth.reddit.com/api/v1/me";
const DEFAULT_USER_AGENT = "web:kavachos-oauth:v1 (by /u/kavachos)";

export const DEFAULT_REDDIT_SCOPES = ["identity"];
const DEFAULT_SCOPES = DEFAULT_REDDIT_SCOPES;

// ---------------------------------------------------------------------------
// Raw response shapes
// ---------------------------------------------------------------------------

interface RedditTokenResponse {
	access_token: string;
	refresh_token?: string;
	expires_in?: number;
	token_type: string;
	scope?: string;
}

interface RedditUserResponse {
	id: string;
	name: string;
	icon_img?: string;
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/**
 * Create a Reddit OAuth provider instance.
 *
 * @example
 * ```typescript
 * const reddit = createRedditProvider({
 *   clientId: process.env.REDDIT_CLIENT_ID,
 *   clientSecret: process.env.REDDIT_CLIENT_SECRET,
 * });
 * ```
 */
export function createRedditProvider(config: OAuthProviderConfig): OAuthProvider {
	const scopes = mergeScopes(DEFAULT_SCOPES, config.scopes);

	async function getAuthorizationUrl(
		state: string,
		codeVerifier: string,
		redirectUri: string,
	): Promise<string> {
		const codeChallenge = await deriveCodeChallenge(codeVerifier);
		const effectiveRedirectUri = config.redirectUri ?? redirectUri;

		const params = new URLSearchParams({
			client_id: config.clientId,
			redirect_uri: effectiveRedirectUri,
			response_type: "code",
			scope: scopes.join(" "),
			state,
			code_challenge: codeChallenge,
			code_challenge_method: "S256",
			// Reddit requires duration=permanent to receive a refresh token.
			duration: "permanent",
		});

		return `${AUTHORIZATION_URL}?${params.toString()}`;
	}

	async function exchangeCode(
		code: string,
		codeVerifier: string,
		redirectUri: string,
	): Promise<OAuthTokens> {
		const effectiveRedirectUri = config.redirectUri ?? redirectUri;

		// Reddit's token endpoint uses HTTP Basic auth instead of posting
		// client credentials in the request body.
		const credentials = btoa(`${config.clientId}:${config.clientSecret}`);

		const body = new URLSearchParams({
			grant_type: "authorization_code",
			code,
			redirect_uri: effectiveRedirectUri,
			code_verifier: codeVerifier,
		});

		const response = await fetch(TOKEN_URL, {
			method: "POST",
			headers: {
				"Content-Type": "application/x-www-form-urlencoded",
				Authorization: `Basic ${credentials}`,
				"User-Agent": DEFAULT_USER_AGENT,
			},
			body: body.toString(),
		});

		if (!response.ok) {
			const text = await response.text();
			throw new Error(`Reddit token exchange failed (${response.status}): ${text}`);
		}

		const raw = (await response.json()) as Record<string, unknown>;
		const data = raw as unknown as RedditTokenResponse;

		return {
			accessToken: data.access_token,
			refreshToken: data.refresh_token,
			expiresIn: data.expires_in,
			tokenType: data.token_type ?? "Bearer",
			raw,
		};
	}

	async function getUserInfo(accessToken: string): Promise<OAuthUserInfo> {
		const response = await fetch(USER_INFO_URL, {
			headers: {
				Authorization: `Bearer ${accessToken}`,
				"User-Agent": DEFAULT_USER_AGENT,
			},
		});

		if (!response.ok) {
			const text = await response.text();
			throw new Error(`Reddit /api/v1/me fetch failed (${response.status}): ${text}`);
		}

		const raw = (await response.json()) as Record<string, unknown>;
		const data = raw as unknown as RedditUserResponse;

		if (!data.id) {
			throw new Error("Reddit user response missing required field: id");
		}

		if (!data.name) {
			throw new Error("Reddit user response missing required field: name");
		}

		// Reddit does not expose email via OAuth. The username (`name`) is the
		// primary identifier. Strip query params from the avatar URL.
		const avatar = data.icon_img ? stripQueryParams(data.icon_img) : undefined;

		return {
			id: data.id,
			// No email — caller must handle the undefined case.
			email: undefined,
			name: data.name,
			avatar,
			raw,
		};
	}

	return {
		id: "reddit",
		name: "Reddit",
		authorizationUrl: AUTHORIZATION_URL,
		tokenUrl: TOKEN_URL,
		userInfoUrl: USER_INFO_URL,
		scopes,
		getAuthorizationUrl,
		exchangeCode,
		getUserInfo,
	};
}

// ---------------------------------------------------------------------------
// Profile normalisation
// ---------------------------------------------------------------------------

export function normalizeProfile(raw: Record<string, unknown>): OAuthUserInfo {
	const data = raw as unknown as RedditUserResponse;

	if (!data.id) {
		throw new Error("Reddit user response missing required field: id");
	}

	if (!data.name) {
		throw new Error("Reddit user response missing required field: name");
	}

	// Reddit does not expose email via OAuth. Strip query params from the avatar URL.
	const avatar = data.icon_img ? stripQueryParams(data.icon_img) : undefined;

	return {
		id: data.id,
		// Reddit does not return email through OAuth; callers must handle this.
		email: undefined,
		name: data.name,
		avatar,
		raw,
	};
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function stripQueryParams(url: string): string {
	try {
		const parsed = new URL(url);
		parsed.search = "";
		return parsed.toString();
	} catch {
		return url;
	}
}

function mergeScopes(defaults: string[], extras?: string[]): string[] {
	if (!extras || extras.length === 0) return defaults;
	const merged = new Set([...defaults, ...extras]);
	return [...merged];
}
