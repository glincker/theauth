/**
 * Google OAuth 2.0 / OIDC provider.
 *
 * Endpoints:
 * - Authorization: https://accounts.google.com/o/oauth2/v2/auth
 * - Token:         https://oauth2.googleapis.com/token
 * - UserInfo:      https://www.googleapis.com/oauth2/v3/userinfo
 *
 * PKCE S256 is always enforced. Google supports it for all client types
 * and the spec mandates it for public clients.
 *
 * Docs: https://developers.google.com/identity/protocols/oauth2
 */

import { deriveCodeChallenge } from "../pkce.js";
import type { OAuthProvider, OAuthProviderConfig, OAuthTokens, OAuthUserInfo } from "../types.js";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const AUTHORIZATION_URL = "https://accounts.google.com/o/oauth2/v2/auth";
const TOKEN_URL = "https://oauth2.googleapis.com/token";
const USER_INFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo";
const DEFAULT_SCOPES = ["openid", "email", "profile"];

// ---------------------------------------------------------------------------
// Raw response shapes
// ---------------------------------------------------------------------------

interface GoogleTokenResponse {
	access_token: string;
	refresh_token?: string;
	expires_in?: number;
	token_type: string;
	id_token?: string;
	scope?: string;
}

interface GoogleUserInfoResponse {
	sub: string;
	email: string;
	email_verified?: boolean;
	name?: string;
	given_name?: string;
	family_name?: string;
	picture?: string;
	locale?: string;
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/**
 * Create a Google OAuth provider instance.
 *
 * @example
 * ```typescript
 * const google = createGoogleProvider({
 *   clientId: process.env.GOOGLE_CLIENT_ID,
 *   clientSecret: process.env.GOOGLE_CLIENT_SECRET,
 * });
 * ```
 */
export function createGoogleProvider(config: OAuthProviderConfig): OAuthProvider {
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
			access_type: "offline", // request refresh token
			prompt: "consent", // always show consent to get refresh token reliably
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
			throw new Error(`Google token exchange failed (${response.status}): ${text}`);
		}

		const raw = (await response.json()) as Record<string, unknown>;
		const data = raw as unknown as GoogleTokenResponse;

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
			throw new Error(`Google userinfo fetch failed (${response.status}): ${text}`);
		}

		const raw = (await response.json()) as Record<string, unknown>;
		const data = raw as unknown as GoogleUserInfoResponse;

		if (!data.sub || !data.email) {
			throw new Error("Google userinfo response missing required fields: sub, email");
		}

		return {
			id: data.sub,
			email: data.email,
			emailVerified: data.email_verified === true,
			name: data.name,
			avatar: data.picture,
			raw,
		};
	}

	return {
		id: "google",
		name: "Google",
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
