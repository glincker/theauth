/**
 * GitLab OAuth 2.0 provider.
 * Notes: - PKCE S256 is supported.
 */

import { deriveCodeChallenge } from "../pkce.js";
import type { OAuthProvider, OAuthProviderConfig, OAuthTokens, OAuthUserInfo } from "../types.js";
import { createRefresher } from "./refresh.js";

const AUTHORIZATION_URL = "https://gitlab.com/oauth/authorize";
const TOKEN_URL = "https://gitlab.com/oauth/token";
const USER_INFO_URL = "https://gitlab.com/api/v4/user";
const DEFAULT_SCOPES = ["read_user"];

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
		refreshTokens: createRefresher({
			providerName: "GitLab",
			tokenUrl: TOKEN_URL,
			clientId: config.clientId,
			clientSecret: config.clientSecret,
		}),
		getUserInfo,
	};
}

function mergeScopes(defaults: string[], extras?: string[]): string[] {
	if (!extras || extras.length === 0) return defaults;
	const merged = new Set([...defaults, ...extras]);
	return [...merged];
}
