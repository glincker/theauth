/**
 * Spotify OAuth 2.0 provider.
 *
 * Endpoints:
 * - Authorization: https://accounts.spotify.com/authorize
 * - Token:         https://accounts.spotify.com/api/token
 * - UserInfo:      https://api.spotify.com/v1/me
 *
 * Notes:
 * - PKCE S256 is supported and encouraged for public clients.
 * - The `user-read-email` scope is required to get the user's email.
 * - The `user-read-private` scope is required to access the user's country
 *   and subscription type. Both are included in the defaults for sign-in.
 * - Email may be absent from the response when the account was created without
 *   one (e.g., via Facebook sign-up on Spotify). Handle the undefined case.
 * - Avatar images are returned as an array of `images`; the first entry is
 *   typically the largest.
 *
 * Docs: https://developer.spotify.com/documentation/web-api/concepts/authorization
 */

import { deriveCodeChallenge } from "../pkce.js";
import type { OAuthProvider, OAuthProviderConfig, OAuthTokens, OAuthUserInfo } from "../types.js";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const AUTHORIZATION_URL = "https://accounts.spotify.com/authorize";
const TOKEN_URL = "https://accounts.spotify.com/api/token";
const USER_INFO_URL = "https://api.spotify.com/v1/me";

export const DEFAULT_SPOTIFY_SCOPES = ["user-read-email", "user-read-private"];

// ---------------------------------------------------------------------------
// Raw response shapes
// ---------------------------------------------------------------------------

interface SpotifyTokenResponse {
	access_token: string;
	refresh_token?: string;
	expires_in?: number;
	token_type: string;
	scope?: string;
}

interface SpotifyImage {
	url: string;
	height?: number | null;
	width?: number | null;
}

interface SpotifyUserResponse {
	id: string;
	display_name?: string | null;
	email?: string;
	images?: SpotifyImage[];
}

// ---------------------------------------------------------------------------
// Profile normalisation
// ---------------------------------------------------------------------------

export function normalizeProfile(raw: Record<string, unknown>): OAuthUserInfo {
	const data = raw as unknown as SpotifyUserResponse;

	if (!data.id) {
		throw new Error("Spotify user response missing required field: id");
	}

	const avatar =
		Array.isArray(data.images) && data.images.length > 0 ? data.images[0]?.url : undefined;

	return {
		id: data.id,
		email: data.email,
		// emailVerified is not provided by Spotify
		name: data.display_name ?? undefined,
		avatar,
		raw,
	};
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/**
 * Create a Spotify OAuth provider instance.
 *
 * @example
 * ```typescript
 * const spotify = createSpotifyProvider({
 *   clientId: process.env.SPOTIFY_CLIENT_ID,
 *   clientSecret: process.env.SPOTIFY_CLIENT_SECRET,
 * });
 * ```
 */
export function createSpotifyProvider(config: OAuthProviderConfig): OAuthProvider {
	const scopes = mergeScopes(DEFAULT_SPOTIFY_SCOPES, config.scopes);

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
			throw new Error(`Spotify token exchange failed (${response.status}): ${text}`);
		}

		const raw = (await response.json()) as Record<string, unknown>;
		const data = raw as unknown as SpotifyTokenResponse;

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
			throw new Error(`Spotify /v1/me fetch failed (${response.status}): ${text}`);
		}

		const raw = (await response.json()) as Record<string, unknown>;
		return normalizeProfile(raw);
	}

	return {
		id: "spotify",
		name: "Spotify",
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
