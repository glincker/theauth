import type { OAuthProvider } from "../types.js";
import { genericOIDC } from "./generic.js";
import { str } from "./presets-helpers.js";

/** Consumer and social OAuth 2.0 preset providers (Facebook through Huggingface). */

/** Facebook (Meta) OAuth 2.0. Docs: https://developers.facebook.com/docs/facebook-login/guides/advanced/manual-flow */
export function facebookProvider(
	clientId: string,
	clientSecret: string,
	scopes?: string[],
): OAuthProvider {
	return genericOIDC({
		id: "facebook",
		name: "Facebook",
		issuer: "https://www.facebook.com",
		clientId,
		clientSecret,
		scopes: scopes ?? ["email", "public_profile"],
		authorizationUrl: "https://www.facebook.com/v18.0/dialog/oauth",
		tokenUrl: "https://graph.facebook.com/v18.0/oauth/access_token",
		userinfoUrl: "https://graph.facebook.com/me?fields=id,email,name,picture",
		// Graph API returns `id`, not the OIDC `sub`, and nests the avatar.
		mapProfile: (raw) => {
			const id = str(raw.id);
			const email = str(raw.email);
			if (!id || !email) return null;
			const picture = raw.picture as { data?: { url?: unknown } } | undefined;
			return { id, email, name: str(raw.name), avatar: str(picture?.data?.url) };
		},
	});
}

/** Spotify OAuth 2.0. Docs: https://developer.spotify.com/documentation/web-api/concepts/authorization */
export function spotifyProvider(
	clientId: string,
	clientSecret: string,
	scopes?: string[],
): OAuthProvider {
	return genericOIDC({
		id: "spotify",
		name: "Spotify",
		issuer: "https://accounts.spotify.com",
		clientId,
		clientSecret,
		scopes: scopes ?? ["user-read-email", "user-read-private"],
		authorizationUrl: "https://accounts.spotify.com/authorize",
		tokenUrl: "https://accounts.spotify.com/api/token",
		userinfoUrl: "https://api.spotify.com/v1/me",
	});
}

/** Twitch OAuth 2.0 / OIDC. Docs: https://dev.twitch.tv/docs/authentication */
export function twitchProvider(
	clientId: string,
	clientSecret: string,
	scopes?: string[],
): OAuthProvider {
	return genericOIDC({
		id: "twitch",
		name: "Twitch",
		issuer: "https://id.twitch.tv/oauth2",
		clientId,
		clientSecret,
		scopes: scopes ?? ["openid", "user:read:email"],
		authorizationUrl: "https://id.twitch.tv/oauth2/authorize",
		tokenUrl: "https://id.twitch.tv/oauth2/token",
		userinfoUrl: "https://id.twitch.tv/oauth2/userinfo",
	});
}

/** Reddit OAuth 2.0. Docs: https://github.com/reddit-archive/reddit/wiki/OAuth2 */
export function redditProvider(
	clientId: string,
	clientSecret: string,
	scopes?: string[],
): OAuthProvider {
	return genericOIDC({
		id: "reddit",
		name: "Reddit",
		issuer: "https://www.reddit.com",
		clientId,
		clientSecret,
		scopes: scopes ?? ["identity"],
		authorizationUrl: "https://www.reddit.com/api/v1/authorize",
		tokenUrl: "https://www.reddit.com/api/v1/access_token",
		userinfoUrl: "https://oauth.reddit.com/api/v1/me",
	});
}

/** Dropbox OAuth 2.0. Docs: https://developers.dropbox.com/oauth-guide */
export function dropboxProvider(
	clientId: string,
	clientSecret: string,
	scopes?: string[],
): OAuthProvider {
	return genericOIDC({
		id: "dropbox",
		name: "Dropbox",
		issuer: "https://www.dropbox.com",
		clientId,
		clientSecret,
		scopes: scopes ?? ["account_info.read"],
		authorizationUrl: "https://www.dropbox.com/oauth2/authorize",
		tokenUrl: "https://api.dropboxapi.com/oauth2/token",
		userinfoUrl: "https://api.dropboxapi.com/2/users/get_current_account",
	});
}

/** Zoom OAuth 2.0 / OIDC. Docs: https://developers.zoom.us/docs/integrations/oauth/ */
export function zoomProvider(
	clientId: string,
	clientSecret: string,
	scopes?: string[],
): OAuthProvider {
	return genericOIDC({
		id: "zoom",
		name: "Zoom",
		issuer: "https://zoom.us",
		clientId,
		clientSecret,
		scopes: scopes ?? ["openid", "profile", "email"],
		authorizationUrl: "https://zoom.us/oauth/authorize",
		tokenUrl: "https://zoom.us/oauth/token",
		userinfoUrl: "https://api.zoom.us/v2/users/me",
	});
}

/** Notion OAuth 2.0. Docs: https://developers.notion.com/docs/authorization */
export function notionProvider(
	clientId: string,
	clientSecret: string,
	scopes?: string[],
): OAuthProvider {
	return genericOIDC({
		id: "notion",
		name: "Notion",
		issuer: "https://api.notion.com",
		clientId,
		clientSecret,
		scopes: scopes ?? [],
		authorizationUrl: "https://api.notion.com/v1/oauth/authorize",
		tokenUrl: "https://api.notion.com/v1/oauth/token",
		userinfoUrl: "https://api.notion.com/v1/users/me",
	});
}

/** Figma OAuth 2.0. Docs: https://www.figma.com/developers/api#authentication */
export function figmaProvider(
	clientId: string,
	clientSecret: string,
	scopes?: string[],
): OAuthProvider {
	return genericOIDC({
		id: "figma",
		name: "Figma",
		issuer: "https://www.figma.com",
		clientId,
		clientSecret,
		scopes: scopes ?? ["file_read"],
		authorizationUrl: "https://www.figma.com/oauth",
		tokenUrl: "https://api.figma.com/v1/oauth/token",
		userinfoUrl: "https://api.figma.com/v1/me",
	});
}

/** Bitbucket OAuth 2.0. Docs: https://developer.atlassian.com/cloud/bitbucket/oauth-2/ */
export function bitbucketProvider(
	clientId: string,
	clientSecret: string,
	scopes?: string[],
): OAuthProvider {
	return genericOIDC({
		id: "bitbucket",
		name: "Bitbucket",
		issuer: "https://bitbucket.org",
		clientId,
		clientSecret,
		scopes: scopes ?? ["account", "email"],
		authorizationUrl: "https://bitbucket.org/site/oauth2/authorize",
		tokenUrl: "https://bitbucket.org/site/oauth2/access_token",
		userinfoUrl: "https://api.bitbucket.org/2.0/user",
	});
}

/** Atlassian OAuth 2.0 (Jira, Confluence, etc.). Docs: https://developer.atlassian.com/cloud/jira/platform/oauth-2-3lo-apps/ */
export function atlassianProvider(
	clientId: string,
	clientSecret: string,
	scopes?: string[],
): OAuthProvider {
	return genericOIDC({
		id: "atlassian",
		name: "Atlassian",
		issuer: "https://auth.atlassian.com",
		clientId,
		clientSecret,
		scopes: scopes ?? ["read:me", "offline_access"],
		authorizationUrl: "https://auth.atlassian.com/authorize",
		tokenUrl: "https://auth.atlassian.com/oauth/token",
		userinfoUrl: "https://api.atlassian.com/me",
	});
}

/** Yahoo OAuth 2.0 / OIDC. Docs: https://developer.yahoo.com/oauth2/guide/ */
export function yahooProvider(
	clientId: string,
	clientSecret: string,
	scopes?: string[],
): OAuthProvider {
	return genericOIDC({
		id: "yahoo",
		name: "Yahoo",
		issuer: "https://api.login.yahoo.com",
		clientId,
		clientSecret,
		scopes: scopes ?? ["openid", "profile", "email"],
		authorizationUrl: "https://api.login.yahoo.com/oauth2/request_auth",
		tokenUrl: "https://api.login.yahoo.com/oauth2/get_token",
		userinfoUrl: "https://api.login.yahoo.com/openid/v1/userinfo",
	});
}

/** LINE Login OAuth 2.0 / OIDC. Docs: https://developers.line.biz/en/docs/line-login/integrate-line-login/ */
export function lineProvider(
	clientId: string,
	clientSecret: string,
	scopes?: string[],
): OAuthProvider {
	return genericOIDC({
		id: "line",
		name: "LINE",
		issuer: "https://access.line.me",
		clientId,
		clientSecret,
		scopes: scopes ?? ["openid", "profile", "email"],
		authorizationUrl: "https://access.line.me/oauth2/v2.1/authorize",
		tokenUrl: "https://api.line.me/oauth2/v2.1/token",
		userinfoUrl: "https://api.line.me/v2/profile",
	});
}

/** Coinbase OAuth 2.0. Docs: https://docs.cdp.coinbase.com/coinbase-app/docs/coinbase-connect-reference */
export function coinbaseProvider(
	clientId: string,
	clientSecret: string,
	scopes?: string[],
): OAuthProvider {
	return genericOIDC({
		id: "coinbase",
		name: "Coinbase",
		issuer: "https://login.coinbase.com",
		clientId,
		clientSecret,
		scopes: scopes ?? ["wallet:user:read", "wallet:user:email"],
		authorizationUrl: "https://login.coinbase.com/oauth2/auth",
		tokenUrl: "https://login.coinbase.com/oauth2/token",
		userinfoUrl: "https://api.coinbase.com/v2/user",
	});
}

/** TikTok OAuth 2.0. Docs: https://developers.tiktok.com/doc/oauth-user-access-token-management */
export function tiktokProvider(
	clientId: string,
	clientSecret: string,
	scopes?: string[],
): OAuthProvider {
	return genericOIDC({
		id: "tiktok",
		name: "TikTok",
		issuer: "https://www.tiktok.com",
		clientId,
		clientSecret,
		scopes: scopes ?? ["user.info.basic"],
		authorizationUrl: "https://www.tiktok.com/v2/auth/authorize/",
		tokenUrl: "https://open.tiktokapis.com/v2/oauth/token/",
		userinfoUrl: "https://open.tiktokapis.com/v2/user/info/",
	});
}

/** PayPal OAuth 2.0 / OIDC. Docs: https://developer.paypal.com/api/rest/authentication/ */
export function paypalProvider(
	clientId: string,
	clientSecret: string,
	scopes?: string[],
): OAuthProvider {
	return genericOIDC({
		id: "paypal",
		name: "PayPal",
		issuer: "https://www.paypal.com",
		clientId,
		clientSecret,
		scopes: scopes ?? ["openid", "email"],
		authorizationUrl: "https://www.paypal.com/signin/authorize",
		tokenUrl: "https://api-m.paypal.com/v1/oauth2/token",
		userinfoUrl: "https://api-m.paypal.com/v1/identity/openidconnect/userinfo?schema=openid",
	});
}

/** Salesforce OAuth 2.0 / OIDC. Docs: https://help.salesforce.com/s/articleView?id=sf.remoteaccess_oauth_flows.htm */
export function salesforceProvider(
	clientId: string,
	clientSecret: string,
	scopes?: string[],
): OAuthProvider {
	return genericOIDC({
		id: "salesforce",
		name: "Salesforce",
		issuer: "https://login.salesforce.com",
		clientId,
		clientSecret,
		scopes: scopes ?? ["openid", "email", "profile"],
		authorizationUrl: "https://login.salesforce.com/services/oauth2/authorize",
		tokenUrl: "https://login.salesforce.com/services/oauth2/token",
		userinfoUrl: "https://login.salesforce.com/services/oauth2/userinfo",
	});
}

/** VK ID OAuth 2.0. Docs: https://id.vk.com/about/business/go/docs/ru/vkid/latest/vkid/sdk/web/get-started */
export function vkProvider(
	clientId: string,
	clientSecret: string,
	scopes?: string[],
): OAuthProvider {
	return genericOIDC({
		id: "vk",
		name: "VK",
		issuer: "https://id.vk.com",
		clientId,
		clientSecret,
		scopes: scopes ?? ["email"],
		authorizationUrl: "https://id.vk.com/authorize",
		tokenUrl: "https://id.vk.com/oauth2/auth",
		userinfoUrl: "https://id.vk.com/oauth2/user_info",
	});
}

/** Kakao OAuth 2.0. Docs: https://developers.kakao.com/docs/latest/en/kakaologin/rest-api */
export function kakaoProvider(
	clientId: string,
	clientSecret: string,
	scopes?: string[],
): OAuthProvider {
	return genericOIDC({
		id: "kakao",
		name: "Kakao",
		issuer: "https://kauth.kakao.com",
		clientId,
		clientSecret,
		scopes: scopes ?? ["account_email", "profile_nickname"],
		authorizationUrl: "https://kauth.kakao.com/oauth/authorize",
		tokenUrl: "https://kauth.kakao.com/oauth/token",
		userinfoUrl: "https://kapi.kakao.com/v2/user/me",
	});
}

/** Naver OAuth 2.0. Docs: https://developers.naver.com/docs/login/api/api.md */
export function naverProvider(
	clientId: string,
	clientSecret: string,
	scopes?: string[],
): OAuthProvider {
	return genericOIDC({
		id: "naver",
		name: "Naver",
		issuer: "https://nid.naver.com",
		clientId,
		clientSecret,
		scopes: scopes ?? ["email", "profile"],
		authorizationUrl: "https://nid.naver.com/oauth2.0/authorize",
		tokenUrl: "https://nid.naver.com/oauth2.0/token",
		userinfoUrl: "https://openapi.naver.com/v1/nid/me",
	});
}

/** Hugging Face OAuth 2.0 / OIDC. Docs: https://huggingface.co/docs/hub/en/oauth */
export function huggingfaceProvider(
	clientId: string,
	clientSecret: string,
	scopes?: string[],
): OAuthProvider {
	return genericOIDC({
		id: "huggingface",
		name: "Hugging Face",
		issuer: "https://huggingface.co",
		clientId,
		clientSecret,
		scopes: scopes ?? ["openid", "profile", "email"],
		authorizationUrl: "https://huggingface.co/oauth/authorize",
		tokenUrl: "https://huggingface.co/oauth/token",
		userinfoUrl: "https://huggingface.co/oauth/userinfo",
	});
}

/** Roblox OAuth 2.0 / OIDC. Docs: https://create.roblox.com/docs/cloud/open-cloud/oauth2-overview */
export function robloxProvider(
	clientId: string,
	clientSecret: string,
	scopes?: string[],
): OAuthProvider {
	return genericOIDC({
		id: "roblox",
		name: "Roblox",
		issuer: "https://apis.roblox.com/oauth",
		clientId,
		clientSecret,
		scopes: scopes ?? ["openid", "profile"],
		authorizationUrl: "https://apis.roblox.com/oauth/v1/authorize",
		tokenUrl: "https://apis.roblox.com/oauth/v1/token",
		userinfoUrl: "https://apis.roblox.com/oauth/v1/userinfo",
	});
}
