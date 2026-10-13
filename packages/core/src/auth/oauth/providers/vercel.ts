/**
 * Sign in with Vercel (OAuth 2.0 / OIDC) provider.
 *
 * Endpoints:
 * - Authorization: https://vercel.com/oauth/authorize
 * - Token:         https://api.vercel.com/login/oauth/token
 * - UserInfo:      https://api.vercel.com/login/oauth/userinfo (POST)
 * - Discovery:     https://vercel.com/.well-known/openid-configuration
 *
 * Notes:
 * - PKCE with S256 is required.
 * - Client credentials go in the form body (`client_secret_post`). Basic,
 *   JWT assertion and `none` are also available per app.
 * - Scopes are `openid`, `email`, `profile` and `offline_access`. Scopes the
 *   app does not have enabled in its dashboard settings are dropped. A
 *   refresh token is issued only when `offline_access` is granted, so pass
 *   it in `scopes` when you need `getAccessToken` refreshes.
 * - The userinfo example in the docs uses POST with a Bearer token.
 * - Userinfo claims: `sub`, `email`, `email_verified`, `name`,
 *   `preferred_username`, `picture`.
 * - This is the Sign in with Vercel flow for apps created under Team
 *   Settings, Apps. It is not the older marketplace integration OAuth flow.
 *
 * Docs: https://vercel.com/docs/sign-in-with-vercel/authorization-server-api
 */

import type { OAuthProvider, OAuthProviderConfig } from "../types.js";
import { genericOIDC } from "./generic.js";
import { str } from "./vendor-util.js";

const AUTHORIZATION_URL = "https://vercel.com/oauth/authorize";
const TOKEN_URL = "https://api.vercel.com/login/oauth/token";
const USER_INFO_URL = "https://api.vercel.com/login/oauth/userinfo";

export const DEFAULT_VERCEL_SCOPES = ["openid", "email", "profile"];

export function createVercelProvider(config: OAuthProviderConfig): OAuthProvider {
	return genericOIDC({
		id: "vercel",
		name: "Vercel",
		issuer: "https://vercel.com",
		clientId: config.clientId,
		clientSecret: config.clientSecret,
		redirectUri: config.redirectUri,
		defaultScopes: DEFAULT_VERCEL_SCOPES,
		scopes: config.scopes,
		authorizationUrl: AUTHORIZATION_URL,
		tokenUrl: TOKEN_URL,
		userinfoUrl: USER_INFO_URL,
		userinfoMethod: "POST",
		mapProfile: (raw) => {
			const id = str(raw.sub);
			const email = str(raw.email);
			if (!id || !email) return null;
			return {
				id,
				email,
				name: str(raw.name) ?? str(raw.preferred_username),
				avatar: str(raw.picture),
				emailVerified: raw.email_verified === true,
			};
		},
	});
}
