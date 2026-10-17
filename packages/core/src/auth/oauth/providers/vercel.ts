/**
 * Sign in with Vercel (OAuth 2.0 / OIDC) provider.
 * Notes:
 * - PKCE with S256 is required. Scopes the app does not have enabled in its dashboard settings are dropped. A refresh token is issued only when `offline_access` is granted, so pass it in `scopes` when you need `getAccessToken` refreshes.
 * - Userinfo claims: `sub`, `email`, `email_verified`, `name`, `preferred_username`, `picture`. It is not the older marketplace integration OAuth flow.
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
