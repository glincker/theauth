/**
 * Twitter / X OAuth 2.0 provider.
 *
 * Endpoints:
 * - Authorization: https://twitter.com/i/oauth2/authorize
 * - Token:         https://api.twitter.com/2/oauth2/token
 * - UserInfo:      https://api.twitter.com/2/users/me
 *
 * Notes:
 * - Twitter OAuth 2.0 (the v2 API) mandates PKCE S256 for all public clients.
 *   Confidential clients may omit PKCE but it is always safer to include it.
 * - The token exchange requires HTTP Basic auth (`client_id:client_secret`)
 *   rather than including credentials in the request body.
 * - The `/2/users/me` endpoint returns a minimal set of fields by default.
 *   Additional fields (profile_image_url, name) must be requested via the
 *   `user.fields` query parameter.
 * - Twitter does not return an email address through the standard OAuth 2.0
 *   flow. Email access requires a separate elevated API access application
 *   and the `tweet.read` scope alone does not grant it.
 * - User IDs are numeric strings and stable across username changes.
 *
 * Docs: https://developer.twitter.com/en/docs/authentication/oauth-2-0/authorization-code
 */

import { deriveCodeChallenge } from "../pkce.js";
import type { OAuthProvider, OAuthProviderConfig, OAuthTokens, OAuthUserInfo } from "../types.js";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const AUTHORIZATION_URL = "https://twitter.com/i/oauth2/authorize";
const TOKEN_URL = "https://api.twitter.com/2/oauth2/token";
const USER_INFO_URL = "https://api.twitter.com/2/users/me";
const USER_FIELDS = "id,name,username,profile_image_url";
const DEFAULT_SCOPES = ["users.read", "tweet.read"];

// ---------------------------------------------------------------------------
// Raw response shapes
// ---------------------------------------------------------------------------

interface TwitterTokenResponse {
	access_token: string;
	refresh_token?: string;
	expires_in?: number;
	token_type: string;
	scope?: string;
}

interface TwitterUserData {
	id: string;
	name?: string;
	username?: string;
	profile_image_url?: string;
}

interface TwitterUserResponse {
	data?: TwitterUserData;
	errors?: Array<{ message: string; title: string }>;
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/**
 * Create a Twitter / X OAuth provider instance.
 *
 * Twitter requires PKCE for all flows. The `clientSecret` is still needed for
 * the token exchange (sent as HTTP Basic auth).
 *
 * @example
 * ```typescript
 * const twitter = createTwitterProvider({
 *   clientId: process.env.TWITTER_CLIENT_ID,
 *   clientSecret: process.env.TWITTER_CLIENT_SECRET,
 * });
 * ```
 */
export function createTwitterProvider(config: OAuthProviderConfig): OAuthProvider {
	const scopes = mergeScopes(DEFAULT_SCOPES, config.scopes);

	async function getAuthorizationUrl(
		state: string,
		codeVerifier: string,
		redirectUri: string,
	): Promise<string> {
		const codeChallenge = await deriveCodeChallenge(codeVerifier);
		const effectiveRedirectUri = config.redirectUri ?? redirectUri;

		const params = new URLSearchParams({
			response_type: "code",
			client_id: config.clientId,
			redirect_uri: effectiveRedirectUri,
			scope: scopes.join(" "),
			state,
			code_challenge: codeChallenge,
			code_challenge_method: "S256",
		});

		return `${AUTHORIZATION_URL}?${params.toString()}`;
	}

	async function exchangeCode(
		code: string,
		codeVerifier: string,
		redirectUri: string,
	): Promise<OAuthTokens> {
		const effectiveRedirectUri = config.redirectUri ?? redirectUri;

		const body = new URLSearchParams({
			grant_type: "authorization_code",
			code,
			code_verifier: codeVerifier,
			redirect_uri: effectiveRedirectUri,
		});

		// Twitter requires client credentials as HTTP Basic auth.
		const credentials = btoa(`${config.clientId}:${config.clientSecret}`);

		const response = await fetch(TOKEN_URL, {
			method: "POST",
			headers: {
				"Content-Type": "application/x-www-form-urlencoded",
				Authorization: `Basic ${credentials}`,
			},
			body: body.toString(),
		});

		if (!response.ok) {
			const text = await response.text();
			throw new Error(`Twitter token exchange failed (${response.status}): ${text}`);
		}

		const raw = (await response.json()) as Record<string, unknown>;
		const data = raw as unknown as TwitterTokenResponse;

		return {
			accessToken: data.access_token,
			refreshToken: data.refresh_token,
			expiresIn: data.expires_in,
			tokenType: data.token_type ?? "Bearer",
			raw,
		};
	}

	async function getUserInfo(accessToken: string): Promise<OAuthUserInfo> {
		const url = `${USER_INFO_URL}?user.fields=${USER_FIELDS}`;

		const response = await fetch(url, {
			headers: { Authorization: `Bearer ${accessToken}` },
		});

		if (!response.ok) {
			const text = await response.text();
			throw new Error(`Twitter /2/users/me fetch failed (${response.status}): ${text}`);
		}

		const raw = (await response.json()) as Record<string, unknown>;
		const parsed = raw as unknown as TwitterUserResponse;

		if (parsed.errors && parsed.errors.length > 0) {
			const msg = parsed.errors.map((e) => `${e.title}: ${e.message}`).join("; ");
			throw new Error(`Twitter API error: ${msg}`);
		}

		const data = parsed.data;
		if (!data?.id) {
			throw new Error("Twitter /2/users/me response missing required field: data.id");
		}

		// Twitter does not provide email through the standard OAuth 2.0 flow.
		// Elevated access is required and not commonly available. We use a
		// placeholder derived from the username so the TheAuth user record
		// remains valid. Callers should treat this as an identifier, not a
		// deliverable email address.
		const email = `${data.username ?? data.id}@twitter.invalid`;

		return {
			id: data.id,
			// Twitter doesn't expose real email via OAuth 2.0 without elevated access.
			// The synthetic address is marked as clearly non-deliverable (.invalid TLD).
			email,
			name: data.name ?? data.username,
			avatar: data.profile_image_url?.replace("_normal", ""),
			raw,
		};
	}

	return {
		id: "twitter",
		name: "Twitter",
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
// Helpers
// ---------------------------------------------------------------------------

function mergeScopes(defaults: string[], extras?: string[]): string[] {
	if (!extras || extras.length === 0) return defaults;
	const merged = new Set([...defaults, ...extras]);
	return [...merged];
}
