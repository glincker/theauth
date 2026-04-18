/**
 * Figma OAuth 2.0 provider.
 *
 * Endpoints:
 * - Authorization: https://www.figma.com/oauth
 * - Token:         https://api.figma.com/v1/oauth/token
 * - UserInfo:      https://api.figma.com/v1/me
 *
 * Notes:
 * - PKCE S256 is supported by Figma's OAuth implementation.
 * - The `file_read` scope is the minimum required for sign-in; it grants
 *   read access to files, projects, and user information.
 * - The email address is always returned; Figma accounts always have one.
 *
 * Docs: https://www.figma.com/developers/api#authentication
 */

import { deriveCodeChallenge } from "../pkce.js";
import type { OAuthProvider, OAuthProviderConfig, OAuthTokens, OAuthUserInfo } from "../types.js";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const AUTHORIZATION_URL = "https://www.figma.com/oauth";
const TOKEN_URL = "https://api.figma.com/v1/oauth/token";
const USER_INFO_URL = "https://api.figma.com/v1/me";

export const DEFAULT_FIGMA_SCOPES = ["file_read"];

// ---------------------------------------------------------------------------
// Raw response shapes
// ---------------------------------------------------------------------------

interface FigmaTokenResponse {
	access_token: string;
	refresh_token?: string;
	expires_in?: number;
	token_type: string;
}

interface FigmaUserResponse {
	id: string;
	email: string;
	handle?: string;
	img_url?: string;
}

// ---------------------------------------------------------------------------
// Profile normalisation
// ---------------------------------------------------------------------------

export function normalizeProfile(raw: Record<string, unknown>): OAuthUserInfo {
	const data = raw as unknown as FigmaUserResponse;

	if (!data.id) {
		throw new Error("Figma user response missing required field: id");
	}

	if (!data.email) {
		throw new Error("Figma user response missing required field: email");
	}

	return {
		id: data.id,
		email: data.email,
		name: data.handle,
		avatar: data.img_url,
		raw,
	};
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/**
 * Create a Figma OAuth provider instance.
 *
 * @example
 * ```typescript
 * const figma = createFigmaProvider({
 *   clientId: process.env.FIGMA_CLIENT_ID,
 *   clientSecret: process.env.FIGMA_CLIENT_SECRET,
 * });
 * ```
 */
export function createFigmaProvider(config: OAuthProviderConfig): OAuthProvider {
	const scopes = mergeScopes(DEFAULT_FIGMA_SCOPES, config.scopes);

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
			client_id: config.clientId,
			client_secret: config.clientSecret,
			redirect_uri: effectiveRedirectUri,
			code,
			code_verifier: codeVerifier,
			grant_type: "authorization_code",
		});

		const response = await fetch(TOKEN_URL, {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body: body.toString(),
		});

		if (!response.ok) {
			const text = await response.text();
			throw new Error(`Figma token exchange failed (${response.status}): ${text}`);
		}

		const raw = (await response.json()) as Record<string, unknown>;
		const data = raw as unknown as FigmaTokenResponse;

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
			throw new Error(`Figma /v1/me fetch failed (${response.status}): ${text}`);
		}

		const raw = (await response.json()) as Record<string, unknown>;
		return normalizeProfile(raw);
	}

	return {
		id: "figma",
		name: "Figma",
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
