/**
 * Twitch OAuth 2.0 provider.
 *
 * Endpoints:
 * - Authorization: https://id.twitch.tv/oauth2/authorize
 * - Token:         https://id.twitch.tv/oauth2/token
 * - UserInfo:      https://api.twitch.tv/helix/users
 *
 * Notes:
 * - PKCE S256 is supported by the Twitch OAuth 2.0 implementation.
 * - The `user:read:email` scope is required to receive the user's email address.
 * - The UserInfo endpoint (/helix/users) requires a `Client-ID` header in
 *   addition to the Bearer token. Without it the request returns 400.
 * - User data is nested under a `data` array; the authenticated user is always
 *   the first element.
 * - Profile image URLs are direct CDN links and may change when the user
 *   updates their profile picture.
 *
 * Docs: https://dev.twitch.tv/docs/authentication/
 */

import { deriveCodeChallenge } from "../pkce.js";
import type { OAuthProvider, OAuthProviderConfig, OAuthTokens, OAuthUserInfo } from "../types.js";
import { createRefresher } from "./refresh.js";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const AUTHORIZATION_URL = "https://id.twitch.tv/oauth2/authorize";
const TOKEN_URL = "https://id.twitch.tv/oauth2/token";
const USER_INFO_URL = "https://api.twitch.tv/helix/users";

export const DEFAULT_TWITCH_SCOPES = ["user:read:email"];
const DEFAULT_SCOPES = DEFAULT_TWITCH_SCOPES;

// ---------------------------------------------------------------------------
// Raw response shapes
// ---------------------------------------------------------------------------

interface TwitchTokenResponse {
	access_token: string;
	refresh_token?: string;
	expires_in?: number;
	token_type: string;
	scope?: string[];
}

interface TwitchUser {
	id: string;
	login: string;
	display_name: string;
	email?: string;
	profile_image_url?: string;
}

interface TwitchUserResponse {
	data: TwitchUser[];
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/**
 * Create a Twitch OAuth provider instance.
 *
 * @example
 * ```typescript
 * const twitch = createTwitchProvider({
 *   clientId: process.env.TWITCH_CLIENT_ID,
 *   clientSecret: process.env.TWITCH_CLIENT_SECRET,
 * });
 * ```
 */
export function createTwitchProvider(config: OAuthProviderConfig): OAuthProvider {
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
			throw new Error(`Twitch token exchange failed (${response.status}): ${text}`);
		}

		const raw = (await response.json()) as Record<string, unknown>;
		const data = raw as unknown as TwitchTokenResponse;

		return {
			accessToken: data.access_token,
			refreshToken: data.refresh_token,
			expiresIn: data.expires_in,
			tokenType: data.token_type ?? "Bearer",
			raw,
		};
	}

	async function getUserInfo(accessToken: string): Promise<OAuthUserInfo> {
		// Twitch's Helix API requires the Client-ID header on every request,
		// even when a valid Bearer token is provided.
		const response = await fetch(USER_INFO_URL, {
			headers: {
				Authorization: `Bearer ${accessToken}`,
				"Client-ID": config.clientId,
			},
		});

		if (!response.ok) {
			const text = await response.text();
			throw new Error(`Twitch /helix/users fetch failed (${response.status}): ${text}`);
		}

		const raw = (await response.json()) as Record<string, unknown>;
		const body = raw as unknown as TwitchUserResponse;

		const user = body.data?.[0];
		if (!user?.id) {
			throw new Error("Twitch user response missing required field: id");
		}

		if (!user.email) {
			throw new Error(
				"Twitch user response has no email. Ensure the `user:read:email` scope is granted.",
			);
		}

		return {
			id: user.id,
			email: user.email,
			name: user.display_name,
			avatar: user.profile_image_url,
			raw,
		};
	}

	return {
		id: "twitch",
		name: "Twitch",
		authorizationUrl: AUTHORIZATION_URL,
		tokenUrl: TOKEN_URL,
		userInfoUrl: USER_INFO_URL,
		scopes,
		getAuthorizationUrl,
		exchangeCode,
		refreshTokens: createRefresher({
			providerName: "Twitch",
			tokenUrl: TOKEN_URL,
			clientId: config.clientId,
			clientSecret: config.clientSecret,
		}),
		getUserInfo,
	};
}

// ---------------------------------------------------------------------------
// Profile normalisation
// ---------------------------------------------------------------------------

export function normalizeProfile(raw: Record<string, unknown>): OAuthUserInfo {
	const body = raw as unknown as TwitchUserResponse;
	const user = body.data?.[0];

	if (!user?.id) {
		throw new Error("Twitch user response missing required field: id");
	}

	if (!user.email) {
		throw new Error(
			"Twitch user response has no email. Ensure the `user:read:email` scope is granted.",
		);
	}

	return {
		id: user.id,
		email: user.email,
		name: user.display_name,
		avatar: user.profile_image_url,
		raw,
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
