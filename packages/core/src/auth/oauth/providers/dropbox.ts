/**
 * Dropbox OAuth 2.0 provider.
 *
 * Endpoints:
 * - Authorization: https://www.dropbox.com/oauth2/authorize
 * - Token:         https://api.dropboxapi.com/oauth2/token
 * - UserInfo:      https://api.dropboxapi.com/2/users/get_current_account (POST)
 *
 * Notes:
 * - PKCE S256 is supported by Dropbox's OAuth 2.0 implementation (since 2021).
 * - The userinfo endpoint is a POST with an empty body (JSON null is the
 *   documented request body). No query params are needed.
 * - The `account_info.read` scope grants access to basic account info including
 *   email, name, and account ID.
 * - Dropbox account IDs start with "dbid:" and are stable across sessions.
 * - The `name` object contains `display_name`, `given_name`, `surname`, etc.
 *
 * Docs: https://developers.dropbox.com/oauth-guide
 */

import { deriveCodeChallenge } from "../pkce.js";
import type { OAuthProvider, OAuthProviderConfig, OAuthTokens, OAuthUserInfo } from "../types.js";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const AUTHORIZATION_URL = "https://www.dropbox.com/oauth2/authorize";
const TOKEN_URL = "https://api.dropboxapi.com/oauth2/token";
const USER_INFO_URL = "https://api.dropboxapi.com/2/users/get_current_account";

export const DEFAULT_DROPBOX_SCOPES = ["account_info.read"];

// ---------------------------------------------------------------------------
// Raw response shapes
// ---------------------------------------------------------------------------

interface DropboxTokenResponse {
	access_token: string;
	refresh_token?: string;
	expires_in?: number;
	token_type: string;
	account_id?: string;
	scope?: string;
}

interface DropboxName {
	display_name?: string;
	given_name?: string;
	surname?: string;
	abbreviated_name?: string;
}

interface DropboxProfilePhoto {
	url?: string;
}

interface DropboxUserResponse {
	account_id: string;
	email?: string;
	email_verified?: boolean;
	name?: DropboxName;
	profile_photo_url?: string;
	profile_photo?: DropboxProfilePhoto;
}

// ---------------------------------------------------------------------------
// Profile normalisation
// ---------------------------------------------------------------------------

export function normalizeProfile(raw: Record<string, unknown>): OAuthUserInfo {
	const data = raw as unknown as DropboxUserResponse;

	if (!data.account_id) {
		throw new Error("Dropbox user response missing required field: account_id");
	}

	if (!data.email) {
		throw new Error("Dropbox user response missing required field: email");
	}

	return {
		id: data.account_id,
		email: data.email,
		name: data.name?.display_name,
		avatar: data.profile_photo_url ?? data.profile_photo?.url,
		raw,
	};
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/**
 * Create a Dropbox OAuth provider instance.
 *
 * @example
 * ```typescript
 * const dropbox = createDropboxProvider({
 *   clientId: process.env.DROPBOX_CLIENT_ID,
 *   clientSecret: process.env.DROPBOX_CLIENT_SECRET,
 * });
 * ```
 */
export function createDropboxProvider(config: OAuthProviderConfig): OAuthProvider {
	const scopes = mergeScopes(DEFAULT_DROPBOX_SCOPES, config.scopes);

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
			token_access_type: "offline",
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
			throw new Error(`Dropbox token exchange failed (${response.status}): ${text}`);
		}

		const raw = (await response.json()) as Record<string, unknown>;
		const data = raw as unknown as DropboxTokenResponse;

		return {
			accessToken: data.access_token,
			refreshToken: data.refresh_token,
			expiresIn: data.expires_in,
			tokenType: data.token_type ?? "Bearer",
			raw,
		};
	}

	async function getUserInfo(accessToken: string): Promise<OAuthUserInfo> {
		// Dropbox's get_current_account endpoint is a POST with a null body.
		const response = await fetch(USER_INFO_URL, {
			method: "POST",
			headers: {
				Authorization: `Bearer ${accessToken}`,
				"Content-Type": "application/json",
			},
			body: "null",
		});

		if (!response.ok) {
			const text = await response.text();
			throw new Error(
				`Dropbox /2/users/get_current_account fetch failed (${response.status}): ${text}`,
			);
		}

		const raw = (await response.json()) as Record<string, unknown>;
		return normalizeProfile(raw);
	}

	return {
		id: "dropbox",
		name: "Dropbox",
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
