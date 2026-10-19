/**
 * Paybin OpenID Connect provider.
 * Docs: https://developers.paybin.io/knowledge-center/oidc
 * Notes:
 * - Authorization Code flow with PKCE (S256, the only method the discovery document lists).
 * - Client credentials go in the form body (`client_secret_post`; Paybin also accepts basic).
 * - Add `offline_access` to `scopes` to receive a refresh token.
 * - The userinfo response carries `email_verified`, which is passed through as `emailVerified`.
 */

import type { OAuthProvider, OAuthProviderConfig } from "../types.js";
import { genericOIDC } from "./generic.js";
import { str } from "./vendor-util.js";

const ISSUER = "https://idp.paybin.io";

export const DEFAULT_PAYBIN_SCOPES = ["openid", "email", "profile"];

export function createPaybinProvider(config: OAuthProviderConfig): OAuthProvider {
	return genericOIDC({
		id: "paybin",
		name: "Paybin",
		issuer: ISSUER,
		clientId: config.clientId,
		clientSecret: config.clientSecret,
		redirectUri: config.redirectUri,
		defaultScopes: DEFAULT_PAYBIN_SCOPES,
		scopes: config.scopes,
		authorizationUrl: `${ISSUER}/connect/authorize`,
		tokenUrl: `${ISSUER}/connect/token`,
		userinfoUrl: `${ISSUER}/connect/userinfo`,
		mapProfile: (raw) => {
			const id = str(raw.sub);
			const email = str(raw.email);
			if (!id || !email) return null;
			return {
				id,
				email,
				name: str(raw.name) ?? str(raw.preferred_username) ?? email,
				avatar: str(raw.picture),
				...(typeof raw.email_verified === "boolean" ? { emailVerified: raw.email_verified } : {}),
			};
		},
	});
}
