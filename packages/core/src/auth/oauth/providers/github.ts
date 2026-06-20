/**
 * GitHub OAuth 2.0 provider.
 *
 * Endpoints:
 * - Authorization: https://github.com/login/oauth/authorize
 * - Token:         https://github.com/login/oauth/access_token
 * - UserInfo:      https://api.github.com/user
 * - Emails:        https://api.github.com/user/emails (for primary verified email)
 *
 * Notes:
 * - GitHub does not natively support PKCE in its OAuth flow, but we send the
 *   `code_challenge` parameter anyway — it is silently ignored, which is safe.
 *   The code verifier is still validated server-side within TheAuth state
 *   storage so the CSRF protection guarantee holds.
 * - The `user:email` scope is required to read the primary email when it is
 *   set to private on the GitHub profile.
 * - GitHub tokens do not carry an `expires_in` field for classic tokens.
 *
 * Docs: https://docs.github.com/en/apps/oauth-apps/building-oauth-apps
 */

import { deriveCodeChallenge } from "../pkce.js";
import type { OAuthProvider, OAuthProviderConfig, OAuthTokens, OAuthUserInfo } from "../types.js";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const AUTHORIZATION_URL = "https://github.com/login/oauth/authorize";
const TOKEN_URL = "https://github.com/login/oauth/access_token";
const USER_URL = "https://api.github.com/user";
const USER_EMAILS_URL = "https://api.github.com/user/emails";
const DEFAULT_SCOPES = ["user:email"];

// ---------------------------------------------------------------------------
// Raw response shapes
// ---------------------------------------------------------------------------

interface GitHubTokenResponse {
	access_token: string;
	refresh_token?: string;
	expires_in?: number;
	token_type: string;
	scope?: string;
	error?: string;
	error_description?: string;
}

interface GitHubUserResponse {
	id: number;
	login: string;
	name?: string;
	email?: string | null;
	avatar_url?: string;
	[key: string]: unknown;
}

interface GitHubEmailEntry {
	email: string;
	primary: boolean;
	verified: boolean;
	visibility: string | null;
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/**
 * Create a GitHub OAuth provider instance.
 *
 * @example
 * ```typescript
 * const github = createGithubProvider({
 *   clientId: process.env.GITHUB_CLIENT_ID,
 *   clientSecret: process.env.GITHUB_CLIENT_SECRET,
 * });
 * ```
 */
export function createGithubProvider(config: OAuthProviderConfig): OAuthProvider {
	const scopes = mergeScopes(DEFAULT_SCOPES, config.scopes);

	async function getAuthorizationUrl(
		state: string,
		codeVerifier: string,
		redirectUri: string,
	): Promise<string> {
		// Derive the challenge even though GitHub ignores it — ensures the same
		// code path is exercised in tests and keeps provider symmetry.
		const codeChallenge = await deriveCodeChallenge(codeVerifier);
		const effectiveRedirectUri = config.redirectUri ?? redirectUri;

		const params = new URLSearchParams({
			client_id: config.clientId,
			redirect_uri: effectiveRedirectUri,
			scope: scopes.join(" "),
			state,
			// Included for symmetry; GitHub ignores unknown parameters.
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
			code,
			redirect_uri: effectiveRedirectUri,
			code_verifier: codeVerifier,
		});

		const response = await fetch(TOKEN_URL, {
			method: "POST",
			headers: {
				"Content-Type": "application/x-www-form-urlencoded",
				Accept: "application/json",
			},
			body: body.toString(),
		});

		if (!response.ok) {
			const text = await response.text();
			throw new Error(`GitHub token exchange failed (${response.status}): ${text}`);
		}

		const raw = (await response.json()) as Record<string, unknown>;
		const data = raw as unknown as GitHubTokenResponse;

		if (data.error) {
			throw new Error(
				`GitHub token exchange error: ${data.error} — ${data.error_description ?? ""}`,
			);
		}

		if (!data.access_token) {
			throw new Error("GitHub token exchange returned no access_token");
		}

		return {
			accessToken: data.access_token,
			refreshToken: data.refresh_token,
			expiresIn: data.expires_in,
			tokenType: data.token_type ?? "bearer",
			raw,
		};
	}

	async function getUserInfo(accessToken: string): Promise<OAuthUserInfo> {
		const headers = {
			Authorization: `Bearer ${accessToken}`,
			Accept: "application/vnd.github+json",
			"X-GitHub-Api-Version": "2022-11-28",
		};

		// Fetch profile
		const profileResponse = await fetch(USER_URL, { headers });
		if (!profileResponse.ok) {
			const text = await profileResponse.text();
			throw new Error(`GitHub user fetch failed (${profileResponse.status}): ${text}`);
		}

		const raw = (await profileResponse.json()) as Record<string, unknown>;
		const profile = raw as GitHubUserResponse;

		// Resolve primary email — profile email may be null when set to private.
		let email = typeof profile.email === "string" ? profile.email : null;

		if (!email) {
			email = await fetchPrimaryEmail(accessToken, headers);
		}

		if (!email) {
			throw new Error(
				"GitHub user has no accessible email. Ensure the user:email scope is granted.",
			);
		}

		return {
			id: String(profile.id),
			email,
			name: profile.name ?? profile.login,
			avatar: profile.avatar_url,
			raw,
		};
	}

	return {
		id: "github",
		name: "GitHub",
		authorizationUrl: AUTHORIZATION_URL,
		tokenUrl: TOKEN_URL,
		userInfoUrl: USER_URL,
		scopes,
		getAuthorizationUrl,
		exchangeCode,
		getUserInfo,
	};
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function fetchPrimaryEmail(
	_accessToken: string,
	headers: Record<string, string>,
): Promise<string | null> {
	const response = await fetch(USER_EMAILS_URL, { headers });
	if (!response.ok) return null;

	const emails = (await response.json()) as GitHubEmailEntry[];
	const primary = emails.find((e) => e.primary && e.verified);
	return primary?.email ?? null;
}

function mergeScopes(defaults: string[], extras?: string[]): string[] {
	if (!extras || extras.length === 0) return defaults;
	const merged = new Set([...defaults, ...extras]);
	return [...merged];
}
