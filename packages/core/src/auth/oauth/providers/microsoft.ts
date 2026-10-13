/**
 * Microsoft identity platform (Entra ID / Azure AD) OAuth 2.0 / OIDC provider.
 *
 * Endpoints (common tenant — works for personal accounts and work/school):
 * - Authorization: https://login.microsoftonline.com/common/oauth2/v2.0/authorize
 * - Token:         https://login.microsoftonline.com/common/oauth2/v2.0/token
 * - UserInfo:      https://graph.microsoft.com/v1.0/me
 *
 * Notes:
 * - PKCE S256 is supported and required for public clients.
 * - `User.Read` is a Microsoft Graph permission, not a standard OIDC scope.
 *   It grants access to the `/me` endpoint.
 * - The `id` field on the Graph `/me` response is the Entra object ID, which
 *   is stable across tenant changes and is safe to use as a primary key.
 * - For single-tenant apps, replace `common` with the tenant ID or domain.
 *
 * Docs: https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow
 */

import { deriveCodeChallenge } from "../pkce.js";
import type { OAuthProvider, OAuthProviderConfig, OAuthTokens, OAuthUserInfo } from "../types.js";
import { createRefresher } from "./refresh.js";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const AUTHORIZATION_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize";
const TOKEN_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/token";
const USER_INFO_URL = "https://graph.microsoft.com/v1.0/me";
const DEFAULT_SCOPES = ["openid", "profile", "email", "User.Read"];

// ---------------------------------------------------------------------------
// Raw response shapes
// ---------------------------------------------------------------------------

interface MicrosoftTokenResponse {
	access_token: string;
	refresh_token?: string;
	expires_in?: number;
	token_type: string;
	id_token?: string;
	scope?: string;
}

interface MicrosoftUserResponse {
	id: string;
	displayName?: string;
	givenName?: string;
	surname?: string;
	mail?: string;
	userPrincipalName?: string;
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/**
 * Create a Microsoft identity platform OAuth provider instance.
 *
 * @example
 * ```typescript
 * const microsoft = createMicrosoftProvider({
 *   clientId: process.env.MICROSOFT_CLIENT_ID,
 *   clientSecret: process.env.MICROSOFT_CLIENT_SECRET,
 * });
 * ```
 */
export function createMicrosoftProvider(config: OAuthProviderConfig): OAuthProvider {
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
			throw new Error(`Microsoft token exchange failed (${response.status}): ${text}`);
		}

		const raw = (await response.json()) as Record<string, unknown>;
		const data = raw as unknown as MicrosoftTokenResponse;

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
			throw new Error(`Microsoft Graph /me fetch failed (${response.status}): ${text}`);
		}

		const raw = (await response.json()) as Record<string, unknown>;
		const data = raw as unknown as MicrosoftUserResponse;

		if (!data.id) {
			throw new Error("Microsoft Graph /me response missing required field: id");
		}

		// `mail` is the primary SMTP address; `userPrincipalName` is the UPN
		// (e.g. user@tenant.onmicrosoft.com) and serves as a fallback for
		// accounts that have no external email alias.
		const email = data.mail ?? data.userPrincipalName;
		if (!email) {
			throw new Error(
				"Microsoft Graph /me response has no email or userPrincipalName. " +
					"Ensure the `email` and `User.Read` scopes are granted.",
			);
		}

		const name =
			data.displayName ?? ([data.givenName, data.surname].filter(Boolean).join(" ") || undefined);

		return {
			id: data.id,
			email,
			name,
			avatar: undefined, // Graph photo requires a separate /me/photo/$value call
			raw,
		};
	}

	return {
		id: "microsoft",
		name: "Microsoft",
		authorizationUrl: AUTHORIZATION_URL,
		tokenUrl: TOKEN_URL,
		userInfoUrl: USER_INFO_URL,
		scopes,
		getAuthorizationUrl,
		exchangeCode,
		refreshTokens: createRefresher({
			providerName: "Microsoft",
			tokenUrl: TOKEN_URL,
			clientId: config.clientId,
			clientSecret: config.clientSecret,
		}),
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
