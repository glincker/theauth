/**
 * Kakao Login (OAuth 2.0) provider.
 * Notes:
 * - `clientId` is the app's REST API key, from the Kakao developer console under the app's platform keys.
 * - The client secret is required at the token endpoint by default (it can be turned off per app in the console).
 * - Kakao's REST guide does not describe PKCE, so no challenge is sent. A refresh issues a new access token, and a new refresh token only when the old one expires within a month. The email is only present when the user consented to `account_email`, and email access needs the app to be approved for it. `is_email_valid` and `is_email_verified` are both required to be true before `emailVerified` is set.
 */

import type { OAuthProvider, OAuthProviderConfig } from "../types.js";
import { genericOIDC } from "./generic.js";
import { asRecord, idString, str } from "./vendor-util.js";

const AUTHORIZATION_URL = "https://kauth.kakao.com/oauth/authorize";
const TOKEN_URL = "https://kauth.kakao.com/oauth/token";
const USER_URL = "https://kapi.kakao.com/v2/user/me";

export const DEFAULT_KAKAO_SCOPES = ["account_email", "profile_nickname", "profile_image"];

export function createKakaoProvider(config: OAuthProviderConfig): OAuthProvider {
	return genericOIDC({
		id: "kakao",
		name: "Kakao",
		issuer: "https://kauth.kakao.com",
		clientId: config.clientId,
		clientSecret: config.clientSecret,
		redirectUri: config.redirectUri,
		defaultScopes: DEFAULT_KAKAO_SCOPES,
		scopes: config.scopes,
		scopeSeparator: ",",
		pkce: false,
		authorizationUrl: AUTHORIZATION_URL,
		tokenUrl: TOKEN_URL,
		userinfoUrl: USER_URL,
		mapProfile: (raw) => {
			const account = asRecord(raw.kakao_account);
			const profile = asRecord(account?.profile);
			const id = idString(raw.id);
			const email = str(account?.email);
			if (!id || !email) return null;
			return {
				id,
				email,
				name: str(profile?.nickname),
				avatar: str(profile?.profile_image_url),
				emailVerified: account?.is_email_verified === true && account?.is_email_valid !== false,
			};
		},
	});
}
