/**
 * Zoom OAuth 2.0 provider.
 *
 * Endpoints:
 * - Authorization: https://zoom.us/oauth/authorize
 * - Token:         https://zoom.us/oauth/token
 * - UserInfo:      https://api.zoom.us/v2/users/me
 *
 * Notes:
 * - PKCE S256 is supported by Zoom's OAuth implementation.
 * - The `user:read` scope grants read access to the authenticated user's
 *   account details including email, name, and profile picture.
 * - Zoom user IDs are alphanumeric strings, not numeric.
 * - The `pic_url` field may be absent when the user has not set a profile photo.
 *
 * Docs: https://developers.zoom.us/docs/integrations/oauth/
 */

import { deriveCodeChallenge } from "../pkce.js";
import type { OAuthProvider, OAuthProviderConfig, OAuthTokens, OAuthUserInfo } from "../types.js";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const AUTHORIZATION_URL = "https://zoom.us/oauth/authorize";
const TOKEN_URL = "https://zoom.us/oauth/token";
const USER_INFO_URL = "https://api.zoom.us/v2/users/me";

export const DEFAULT_ZOOM_SCOPES = ["user:read"];

// ---------------------------------------------------------------------------
// Raw response shapes
// ---------------------------------------------------------------------------

interface ZoomTokenResponse {
	access_token: string;
	refresh_token?: string;
	expires_in?: number;
	token_type: string;
	scope?: string;
}

interface ZoomUserResponse {
	id: string;
	email: string;
	first_name?: string;
	last_name?: string;
	display_name?: string;
	pic_url?: string;
}

// ---------------------------------------------------------------------------
// Profile normalisation
// ---------------------------------------------------------------------------

export function normalizeProfile(raw: Record<string, unknown>): OAuthUserInfo {
	const data = raw as unknown as ZoomUserResponse;

	if (!data.id) {
		throw new Error("Zoom user response missing required field: id");
	}

	if (!data.email) {
		throw new Error("Zoom user response missing required field: email");
	}

	const joinedName = [data.first_name, data.last_name].filter(Boolean).join(" ");
	const name = data.display_name ?? (joinedName.length > 0 ? joinedName : undefined);

	return {
		id: data.id,
		email: data.email,
		name,
		avatar: data.pic_url,
		raw,
	};
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/**
 * Create a Zoom OAuth provider instance.
 *
 * @example
 * ```typescript
 * const zoom = createZoomProvider({
 *   clientId: process.env.ZOOM_CLIENT_ID,
 *   clientSecret: process.env.ZOOM_CLIENT_SECRET,
 * });
 * ```
 */
export function createZoomProvider(config: OAuthProviderConfig): OAuthProvider {
	const scopes = mergeScopes(DEFAULT_ZOOM_SCOPES, config.scopes);

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
			client_id: config.clientId,
			client_secret: config.clientSecret,
			code,
			code_verifier: codeVerifier,
			redirect_uri: effectiveRedirectUri,
		});

		const response = await fetch(TOKEN_URL, {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body: body.toString(),
		});

		if (!response.ok) {
			const text = await response.text();
			throw new Error(`Zoom token exchange failed (${response.status}): ${text}`);
		}

		const raw = (await response.json()) as Record<string, unknown>;
		const data = raw as unknown as ZoomTokenResponse;

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
			headers: { Authorization: `Bearer ${accessToken}` },
		});

		if (!response.ok) {
			const text = await response.text();
			throw new Error(`Zoom /v2/users/me fetch failed (${response.status}): ${text}`);
		}

		const raw = (await response.json()) as Record<string, unknown>;
		return normalizeProfile(raw);
	}

	return {
		id: "zoom",
		name: "Zoom",
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
