/**
 * Apple Sign In provider (OAuth 2.0 / OIDC).
 * Notes:
 * - Apple does not expose a dedicated UserInfo endpoint. On subsequent authorizations the `user` form-post field is absent, only the `id_token` carries the `sub` and `email` claims.
 * - `response_mode` must be `form_post` when requesting the `name` scope, because Apple POSTs back a `user` JSON field alongside the code.
 * - The `name` scope only delivers user data on the *first* authorization. Store it immediately; subsequent logins will not include it.
 */

import { decodeJwt } from "jose";
import { deriveCodeChallenge } from "../pkce.js";
import type { OAuthProvider, OAuthProviderConfig, OAuthTokens, OAuthUserInfo } from "../types.js";

const AUTHORIZATION_URL = "https://appleid.apple.com/auth/authorize";
const TOKEN_URL = "https://appleid.apple.com/auth/token";
const DEFAULT_SCOPES = ["name", "email"];

interface AppleTokenResponse {
	access_token: string;
	refresh_token?: string;
	expires_in?: number;
	token_type: string;
	id_token?: string;
}

interface AppleIdTokenClaims {
	sub: string;
	email?: string;
	email_verified?: boolean | string;
	is_private_email?: boolean | string;
}

/**
 * Create an Apple Sign In provider instance.
 * Apple requires a JWT client secret (signed with your private key) rather than a static secret.
 *
 * @example
 * ```typescript
 * const apple = createAppleProvider({
 *   clientId: process.env.APPLE_CLIENT_ID,       // Services ID, e.g. com.example.app
 *   clientSecret: appleClientSecretJwt,           // ES256 JWT generated from private key
 * });
 * ```
 */
export function createAppleProvider(config: OAuthProviderConfig): OAuthProvider {
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
			// `form_post` is required when requesting `name` scope so Apple
			// can include the `user` JSON field in the POST body.
			response_mode: "form_post",
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
			throw new Error(`Apple token exchange failed (${response.status}): ${text}`);
		}

		const raw = (await response.json()) as Record<string, unknown>;
		const data = raw as unknown as AppleTokenResponse;

		return {
			accessToken: data.access_token,
			refreshToken: data.refresh_token,
			expiresIn: data.expires_in,
			tokenType: data.token_type ?? "Bearer",
			raw,
		};
	}

	async function getUserInfo(_accessToken: string, tokens?: OAuthTokens): Promise<OAuthUserInfo> {
		// Apple does not have a userinfo endpoint. Claims come from the id_token.
		const idToken = tokens?.raw.id_token;
		if (typeof idToken !== "string") {
			throw new Error(
				"Apple getUserInfo requires the id_token from the token response. " +
					"Pass the full OAuthTokens object as the second argument.",
			);
		}

		// Decode without verification here, signature verification should be
		// done at the module layer using Apple's published JWKS if needed.
		const claims = decodeJwt(idToken) as unknown as AppleIdTokenClaims;

		if (!claims.sub) {
			throw new Error("Apple id_token missing required claim: sub");
		}

		if (!claims.email) {
			throw new Error(
				"Apple id_token missing email claim. The `email` scope may not have been granted, " +
					"or this is not the first authorization for this user.",
			);
		}

		return {
			id: claims.sub,
			email: claims.email,
			// Apple does not include a display name in the id_token. The `name`
			// object is only available in the form-post `user` field on first auth.
			// Callers should merge it in from the form body before storing.
			name: undefined,
			avatar: undefined,
			raw: claims as unknown as Record<string, unknown>,
		};
	}

	return {
		id: "apple",
		name: "Apple",
		authorizationUrl: AUTHORIZATION_URL,
		tokenUrl: TOKEN_URL,
		userInfoUrl: "",
		scopes,
		getAuthorizationUrl,
		exchangeCode,
		// Cast needed because the base interface signature uses one argument;
		// Apple extends it with an optional second param for the token object.
		getUserInfo: getUserInfo as OAuthProvider["getUserInfo"],
	};
}

function mergeScopes(defaults: string[], extras?: string[]): string[] {
	if (!extras || extras.length === 0) return defaults;
	const merged = new Set([...defaults, ...extras]);
	return [...merged];
}
