/**
 * GitLab OAuth 2.0 provider.
 *
 * Endpoints (gitlab.com — self-managed instances replace the base URL):
 * - Authorization: https://gitlab.com/oauth/authorize
 * - Token:         https://gitlab.com/oauth/token
 * - UserInfo:      https://gitlab.com/api/v4/user
 *
 * Notes:
 * - PKCE S256 is supported.
 * - The `read_user` scope grants access to the `/api/v4/user` endpoint which
 *   returns the authenticated user's profile including email.
 * - GitLab user IDs are integers; they are converted to strings for the
 *   TheAuth normalized format.
 * - For self-managed GitLab instances, override the URLs by providing a
 *   custom base URL and constructing the provider accordingly.
 *
 * Docs: https://docs.gitlab.com/ee/api/oauth2.html
 */

import { deriveCodeChallenge } from "../pkce.js";
import type { OAuthProvider, OAuthProviderConfig, OAuthTokens, OAuthUserInfo } from "../types.js";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const AUTHORIZATION_URL = "https://gitlab.com/oauth/authorize";
const TOKEN_URL = "https://gitlab.com/oauth/token";
const USER_INFO_URL = "https://gitlab.com/api/v4/user";
const DEFAULT_SCOPES = ["read_user"];

// ---------------------------------------------------------------------------
// Raw response shapes
// ---------------------------------------------------------------------------

interface GitLabTokenResponse {
	access_token: string;
	refresh_token?: string;
	expires_in?: number;
	token_type: string;
	scope?: string;
}

interface GitLabUserResponse {
	id: number;
	username: string;
	name?: string;
	email?: string;
	public_email?: string;
	avatar_url?: string;
	state?: string;
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/**
 * Create a GitLab OAuth provider instance.
 *
 * @example
 * ```typescript
 * const gitlab = createGitlabProvider({
 *   clientId: process.env.GITLAB_CLIENT_ID,
 *   clientSecret: process.env.GITLAB_CLIENT_SECRET,
 * });
 * ```
 */
export function createGitlabProvider(config: OAuthProviderConfig): OAuthProvider {
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
			throw new Error(`GitLab token exchange failed (${response.status}): ${text}`);
		}

		const raw = (await response.json()) as Record<string, unknown>;
		const data = raw as unknown as GitLabTokenResponse;

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
			throw new Error(`GitLab /api/v4/user fetch failed (${response.status}): ${text}`);
		}

		const raw = (await response.json()) as Record<string, unknown>;
		const data = raw as unknown as GitLabUserResponse;

		if (!data.id) {
			throw new Error("GitLab user response missing required field: id");
		}

		// `email` is the primary email. `public_email` is what the user chose
		// to expose publicly. Both may be absent if the account has privacy
		// settings that restrict visibility.
		const email = data.email ?? data.public_email;
		if (!email) {
			throw new Error(
				"GitLab user response has no email. The account may have restricted email visibility.",
			);
		}

		return {
			id: String(data.id),
			email,
			name: data.name ?? data.username,
			avatar: data.avatar_url,
			raw,
		};
	}

	return {
		id: "gitlab",
		name: "GitLab",
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
