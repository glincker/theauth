/**
 * LinkedIn OAuth 2.0 / OIDC provider.
 *
 * Endpoints:
 * - Authorization: https://www.linkedin.com/oauth/v2/authorization
 * - Token:         https://www.linkedin.com/oauth/v2/accessToken
 * - UserInfo:      https://api.linkedin.com/v2/userinfo (OIDC endpoint)
 *
 * Notes:
 * - LinkedIn's OIDC userinfo endpoint (`/v2/userinfo`) is available when the
 *   `openid` scope is requested. It returns standard OIDC claims including
 *   `sub`, `name`, `email`, and `picture`.
 * - PKCE is not supported by LinkedIn's OAuth server. The code challenge is
 *   sent for symmetry but silently ignored. CSRF protection via `state` still
 *   applies within TheAuth.
 * - The `sub` claim is the LinkedIn member ID and is stable across sessions.
 *
 * Docs: https://learn.microsoft.com/en-us/linkedin/consumer/integrations/self-serve/sign-in-with-linkedin-v2
 */

import { deriveCodeChallenge } from "../pkce.js";
import type { OAuthProvider, OAuthProviderConfig, OAuthTokens, OAuthUserInfo } from "../types.js";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const AUTHORIZATION_URL = "https://www.linkedin.com/oauth/v2/authorization";
const TOKEN_URL = "https://www.linkedin.com/oauth/v2/accessToken";
const USER_INFO_URL = "https://api.linkedin.com/v2/userinfo";
const DEFAULT_SCOPES = ["openid", "profile", "email"];

// ---------------------------------------------------------------------------
// Raw response shapes
// ---------------------------------------------------------------------------

interface LinkedInTokenResponse {
	access_token: string;
	refresh_token?: string;
	expires_in?: number;
	token_type?: string;
	scope?: string;
}

interface LinkedInUserInfoResponse {
	sub: string;
	name?: string;
	given_name?: string;
	family_name?: string;
	email?: string;
	email_verified?: boolean;
	picture?: string;
	locale?: string | { country: string; language: string };
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/**
 * Create a LinkedIn OAuth provider instance.
 *
 * @example
 * ```typescript
 * const linkedin = createLinkedInProvider({
 *   clientId: process.env.LINKEDIN_CLIENT_ID,
 *   clientSecret: process.env.LINKEDIN_CLIENT_SECRET,
 * });
 * ```
 */
export function createLinkedInProvider(config: OAuthProviderConfig): OAuthProvider {
	const scopes = mergeScopes(DEFAULT_SCOPES, config.scopes);

	async function getAuthorizationUrl(
		state: string,
		codeVerifier: string,
		redirectUri: string,
	): Promise<string> {
		// Derive challenge for symmetry; LinkedIn ignores it.
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
			client_id: config.clientId,
			client_secret: config.clientSecret,
			code,
			redirect_uri: effectiveRedirectUri,
			code_verifier: codeVerifier,
		});

		const response = await fetch(TOKEN_URL, {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body: body.toString(),
		});

		if (!response.ok) {
			const text = await response.text();
			throw new Error(`LinkedIn token exchange failed (${response.status}): ${text}`);
		}

		const raw = (await response.json()) as Record<string, unknown>;
		const data = raw as unknown as LinkedInTokenResponse;

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
			throw new Error(`LinkedIn /v2/userinfo fetch failed (${response.status}): ${text}`);
		}

		const raw = (await response.json()) as Record<string, unknown>;
		const data = raw as unknown as LinkedInUserInfoResponse;

		if (!data.sub) {
			throw new Error("LinkedIn userinfo response missing required field: sub");
		}

		if (!data.email) {
			throw new Error(
				"LinkedIn userinfo response has no email. Ensure the `email` and `openid` scopes are granted.",
			);
		}

		const name =
			data.name ?? ([data.given_name, data.family_name].filter(Boolean).join(" ") || undefined);

		return {
			id: data.sub,
			email: data.email,
			name,
			avatar: data.picture,
			raw,
		};
	}

	return {
		id: "linkedin",
		name: "LinkedIn",
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
