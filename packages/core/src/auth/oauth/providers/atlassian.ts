/**
 * Atlassian OAuth 2.0 (3LO) provider.
 *
 * Endpoints:
 * - Authorization: https://auth.atlassian.com/authorize
 * - Token:         https://auth.atlassian.com/oauth/token
 * - UserInfo:      https://api.atlassian.com/me
 *
 * Notes:
 * - PKCE S256 is supported by Atlassian's OAuth 2.0 implementation.
 * - The `audience` parameter (`api.atlassian.com`) is required on the
 *   authorization URL. Without it, tokens will not be accepted by the
 *   Atlassian APIs.
 * - The `read:me` scope grants access to the user's identity (account ID,
 *   email, name, avatar). Add `offline_access` if refresh tokens are needed.
 * - Atlassian account IDs are in the format `557058:xxxxxxxx-xxxx-...`.
 *
 * Docs: https://developer.atlassian.com/cloud/jira/platform/oauth-2-3lo-apps/
 */

import { deriveCodeChallenge } from "../pkce.js";
import type { OAuthProvider, OAuthProviderConfig, OAuthTokens, OAuthUserInfo } from "../types.js";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const AUTHORIZATION_URL = "https://auth.atlassian.com/authorize";
const TOKEN_URL = "https://auth.atlassian.com/oauth/token";
const USER_INFO_URL = "https://api.atlassian.com/me";
const ATLASSIAN_AUDIENCE = "api.atlassian.com";

export const DEFAULT_ATLASSIAN_SCOPES = ["read:me"];

// ---------------------------------------------------------------------------
// Raw response shapes
// ---------------------------------------------------------------------------

interface AtlassianTokenResponse {
	access_token: string;
	refresh_token?: string;
	expires_in?: number;
	token_type: string;
	scope?: string;
}

interface AtlassianUserResponse {
	account_id: string;
	email?: string;
	name?: string;
	picture?: string;
	account_type?: string;
}

// ---------------------------------------------------------------------------
// Profile normalisation
// ---------------------------------------------------------------------------

export function normalizeProfile(raw: Record<string, unknown>): OAuthUserInfo {
	const data = raw as unknown as AtlassianUserResponse;

	if (!data.account_id) {
		throw new Error("Atlassian user response missing required field: account_id");
	}

	return {
		id: data.account_id,
		email: data.email,
		name: data.name,
		avatar: data.picture,
		raw,
	};
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/**
 * Create an Atlassian OAuth provider instance.
 *
 * @example
 * ```typescript
 * const atlassian = createAtlassianProvider({
 *   clientId: process.env.ATLASSIAN_CLIENT_ID,
 *   clientSecret: process.env.ATLASSIAN_CLIENT_SECRET,
 * });
 * ```
 */
export function createAtlassianProvider(config: OAuthProviderConfig): OAuthProvider {
	const scopes = mergeScopes(DEFAULT_ATLASSIAN_SCOPES, config.scopes);

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
			// Required: instructs Atlassian which API audience to issue tokens for.
			audience: ATLASSIAN_AUDIENCE,
			prompt: "consent",
		});

		return `${AUTHORIZATION_URL}?${params.toString()}`;
	}

	async function exchangeCode(
		code: string,
		codeVerifier: string,
		redirectUri: string,
	): Promise<OAuthTokens> {
		const effectiveRedirectUri = config.redirectUri ?? redirectUri;

		const response = await fetch(TOKEN_URL, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({
				grant_type: "authorization_code",
				client_id: config.clientId,
				client_secret: config.clientSecret,
				code,
				code_verifier: codeVerifier,
				redirect_uri: effectiveRedirectUri,
			}),
		});

		if (!response.ok) {
			const text = await response.text();
			throw new Error(`Atlassian token exchange failed (${response.status}): ${text}`);
		}

		const raw = (await response.json()) as Record<string, unknown>;
		const data = raw as unknown as AtlassianTokenResponse;

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
			throw new Error(`Atlassian /me fetch failed (${response.status}): ${text}`);
		}

		const raw = (await response.json()) as Record<string, unknown>;
		return normalizeProfile(raw);
	}

	return {
		id: "atlassian",
		name: "Atlassian",
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
