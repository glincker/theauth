/**
 * Kick OAuth 2.1 provider.
 *
 * Endpoints:
 * - Authorization: https://id.kick.com/oauth/authorize
 * - Token:         https://id.kick.com/oauth/token
 * - Profile:       https://api.kick.com/public/v1/users
 *
 * Notes:
 * - PKCE with S256 is required.
 * - Client credentials go in the form body.
 * - The `user:read` scope is needed for the profile call, which returns
 *   `{ data: [{ user_id, name, email, profile_picture }] }`. `user_id` is a
 *   number and is stringified.
 * - The profile call is on a different host (`api.kick.com`) from the auth
 *   server (`id.kick.com`). Without a user id in the query it returns the
 *   token owner.
 * - Kick does not say whether the email is verified, so `emailVerified`
 *   stays unset.
 * - User tokens come with a refresh token.
 *
 * Docs: https://docs.kick.com/getting-started/generating-tokens-oauth2-flow
 *       https://docs.kick.com/apis/users
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
