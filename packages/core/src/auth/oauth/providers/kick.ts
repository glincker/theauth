/**
 * Kick OAuth 2.1 provider.
 * Notes:
 * - PKCE with S256 is required.
 * - Kick does not say whether the email is verified, so `emailVerified` stays unset.
 * - User tokens come with a refresh token.
 */

import type { OAuthProvider, OAuthProviderConfig } from "../types.js";
import { genericOIDC } from "./generic.js";
import { asRecord, idString, str } from "./vendor-util.js";

const AUTHORIZATION_URL = "https://id.kick.com/oauth/authorize";
const TOKEN_URL = "https://id.kick.com/oauth/token";
const USER_URL = "https://api.kick.com/public/v1/users";

export const DEFAULT_KICK_SCOPES = ["user:read"];

export function createKickProvider(config: OAuthProviderConfig): OAuthProvider {
	return genericOIDC({
		id: "kick",
		name: "Kick",
		issuer: "https://id.kick.com",
		clientId: config.clientId,
		clientSecret: config.clientSecret,
		redirectUri: config.redirectUri,
		defaultScopes: DEFAULT_KICK_SCOPES,
		scopes: config.scopes,
		authorizationUrl: AUTHORIZATION_URL,
		tokenUrl: TOKEN_URL,
		userinfoUrl: USER_URL,
		mapProfile: (raw) => {
			const list = Array.isArray(raw.data) ? raw.data : [];
			const user = asRecord(list[0]);
			const id = idString(user?.user_id);
			const email = str(user?.email);
			if (!id || !email) return null;
			return { id, email, name: str(user?.name), avatar: str(user?.profile_picture) };
		},
	});
}
