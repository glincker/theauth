/**
 * Slack OAuth 2.0 / OIDC provider.
 *
 * Endpoints:
 * - Authorization: https://slack.com/oauth/v2/authorize
 * - Token:         https://slack.com/api/oauth.v2.access
 * - UserInfo:      https://slack.com/api/openid.connect.userInfo
 *
 * Notes:
 * - Slack's v2 OAuth uses OpenID Connect for user sign-in. The
 *   `openid.connect.userInfo` endpoint returns OIDC-standard claims.
 * - The token exchange response has a nested structure: `authed_user.access_token`
 *   for the user token and a bot token at the top level when bot scopes are
 *   included. For sign-in we want the user token.
 * - PKCE is not natively supported by Slack's OAuth v2 server. The code
 *   challenge is sent but silently ignored — CSRF protection via `state` still
 *   applies within TheAuth.
 * - Slack user IDs are workspace-scoped, not global. The `sub` claim from the
 *   OIDC userinfo endpoint is the globally unique identifier across workspaces.
 *
 * Docs: https://api.slack.com/authentication/sign-in-with-slack
 */

import { deriveCodeChallenge } from "../pkce.js";
import type { OAuthProvider, OAuthProviderConfig, OAuthTokens, OAuthUserInfo } from "../types.js";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const AUTHORIZATION_URL = "https://slack.com/oauth/v2/authorize";
const TOKEN_URL = "https://slack.com/api/oauth.v2.access";
const USER_INFO_URL = "https://slack.com/api/openid.connect.userInfo";

export const DEFAULT_SLACK_SCOPES = ["openid", "profile", "email"];
const DEFAULT_SCOPES = DEFAULT_SLACK_SCOPES;

// ---------------------------------------------------------------------------
// Raw response shapes
// ---------------------------------------------------------------------------

interface SlackAuthedUser {
	id: string;
	scope?: string;
	access_token?: string;
	token_type?: string;
}

interface SlackTokenResponse {
	ok: boolean;
	access_token?: string;
	token_type?: string;
	authed_user?: SlackAuthedUser;
	error?: string;
}

interface SlackUserInfoResponse {
	ok: boolean;
	sub?: string;
	email?: string;
	name?: string;
	picture?: string;
	"https://slack.com/user_id"?: string;
	error?: string;
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/**
 * Create a Slack OAuth provider instance.
 *
 * @example
 * ```typescript
 * const slack = createSlackProvider({
 *   clientId: process.env.SLACK_CLIENT_ID,
 *   clientSecret: process.env.SLACK_CLIENT_SECRET,
 * });
 * ```
 */
export function createSlackProvider(config: OAuthProviderConfig): OAuthProvider {
	const scopes = mergeScopes(DEFAULT_SCOPES, config.scopes);

	async function getAuthorizationUrl(
		state: string,
		codeVerifier: string,
		redirectUri: string,
	): Promise<string> {
		// Derive the challenge for symmetry even though Slack ignores it.
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
			throw new Error(`Slack token exchange failed (${response.status}): ${text}`);
		}

		const raw = (await response.json()) as Record<string, unknown>;
		const data = raw as unknown as SlackTokenResponse;

		if (!data.ok) {
			throw new Error(`Slack token exchange error: ${data.error ?? "unknown"}`);
		}

		// Prefer the user token from authed_user when present. The top-level
		// access_token is a bot token when bot scopes are included.
		const accessToken = data.authed_user?.access_token ?? data.access_token;
		if (!accessToken) {
			throw new Error("Slack token exchange returned no access_token");
		}

		return {
			accessToken,
			refreshToken: undefined,
			expiresIn: undefined,
			tokenType: data.authed_user?.token_type ?? data.token_type ?? "Bearer",
			raw,
		};
	}

	async function getUserInfo(accessToken: string): Promise<OAuthUserInfo> {
		const response = await fetch(USER_INFO_URL, {
			headers: { Authorization: `Bearer ${accessToken}` },
		});

		if (!response.ok) {
			const text = await response.text();
			throw new Error(`Slack openid.connect.userInfo fetch failed (${response.status}): ${text}`);
		}

		const raw = (await response.json()) as Record<string, unknown>;
		const data = raw as unknown as SlackUserInfoResponse;

		if (!data.ok) {
			throw new Error(`Slack userInfo error: ${data.error ?? "unknown"}`);
		}

		const id = data.sub ?? data["https://slack.com/user_id"];
		if (!id) {
			throw new Error("Slack userInfo response missing required field: sub");
		}

		if (!data.email) {
			throw new Error("Slack userInfo response has no email. Ensure the `email` scope is granted.");
		}

		return {
			id,
			email: data.email,
			name: data.name,
			avatar: data.picture,
			raw,
		};
	}

	return {
		id: "slack",
		name: "Slack",
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
// Profile normalisation
// ---------------------------------------------------------------------------

export function normalizeProfile(raw: Record<string, unknown>): OAuthUserInfo {
	const data = raw as unknown as SlackUserInfoResponse;

	if (!data.ok) {
		throw new Error(`Slack userInfo error: ${data.error ?? "unknown"}`);
	}

	const id = data.sub ?? data["https://slack.com/user_id"];
	if (!id) {
		throw new Error("Slack userInfo response missing required field: sub");
	}

	if (!data.email) {
		throw new Error("Slack userInfo response has no email. Ensure the `email` scope is granted.");
	}

	return {
		id,
		email: data.email,
		name: data.name,
		avatar: data.picture,
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
