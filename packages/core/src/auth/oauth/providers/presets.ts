/**
 * Preset OAuth provider configs.
 *
 * Each export is a factory function that takes `(clientId, clientSecret)`
 * and returns a config accepted by `genericOIDC` or usable directly as a
 * plain provider when the provider does not support OIDC discovery.
 *
 * OIDC-capable providers (Auth0, Okta) use `genericOIDC` and require the
 * caller to supply their tenant/domain as a third argument.
 *
 * All other presets return a `GenericOIDCConfig`-compatible object with
 * explicit endpoints so they work without any network discovery call.
 */

import type { OAuthProvider } from "../types.js";
import type { GenericOIDCConfig } from "./generic.js";
import { genericOIDC } from "./generic.js";

// ---------------------------------------------------------------------------
// Re-export type so callers can annotate their config objects
// ---------------------------------------------------------------------------

export type { GenericOIDCConfig };

// ---------------------------------------------------------------------------
// Providers that use explicit endpoints (no OIDC discovery)
// ---------------------------------------------------------------------------

/**
 * Facebook (Meta) OAuth 2.0.
 *
 * Docs: https://developers.facebook.com/docs/facebook-login/guides/advanced/manual-flow
 */
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

/**
 * Spotify OAuth 2.0.
 *
 * Docs: https://developer.spotify.com/documentation/web-api/concepts/authorization
 */
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

/**
 * Twitch OAuth 2.0 / OIDC.
 *
 * Docs: https://dev.twitch.tv/docs/authentication
 */
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

/**
 * Reddit OAuth 2.0.
 *
 * Docs: https://github.com/reddit-archive/reddit/wiki/OAuth2
 */
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

/**
 * Dropbox OAuth 2.0.
 *
 * Docs: https://developers.dropbox.com/oauth-guide
 */
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

/**
 * Zoom OAuth 2.0 / OIDC.
 *
 * Docs: https://developers.zoom.us/docs/integrations/oauth/
 */
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

/**
 * Notion OAuth 2.0.
 *
 * Docs: https://developers.notion.com/docs/authorization
 */
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

/**
 * Figma OAuth 2.0.
 *
 * Docs: https://www.figma.com/developers/api#authentication
 */
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

/**
 * Bitbucket OAuth 2.0.
 *
 * Docs: https://developer.atlassian.com/cloud/bitbucket/oauth-2/
 */
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

/**
 * Atlassian OAuth 2.0 (Jira, Confluence, etc.).
 *
 * Docs: https://developer.atlassian.com/cloud/jira/platform/oauth-2-3lo-apps/
 */
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

/**
 * Yahoo OAuth 2.0 / OIDC.
 *
 * Docs: https://developer.yahoo.com/oauth2/guide/
 */
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

/**
 * LINE Login OAuth 2.0 / OIDC.
 *
 * Docs: https://developers.line.biz/en/docs/line-login/integrate-line-login/
 */
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

/**
 * Coinbase OAuth 2.0.
 *
 * Docs: https://docs.cdp.coinbase.com/coinbase-app/docs/coinbase-connect-reference
 */
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

// ---------------------------------------------------------------------------
// New preset providers
// ---------------------------------------------------------------------------

/**
 * TikTok OAuth 2.0.
 *
 * Docs: https://developers.tiktok.com/doc/oauth-user-access-token-management
 */
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

/**
 * PayPal OAuth 2.0 / OIDC.
 *
 * Docs: https://developer.paypal.com/api/rest/authentication/
 */
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

/**
 * Salesforce OAuth 2.0 / OIDC.
 *
 * Docs: https://help.salesforce.com/s/articleView?id=sf.remoteaccess_oauth_flows.htm
 */
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

/**
 * VK ID OAuth 2.0.
 *
 * Docs: https://id.vk.com/about/business/go/docs/ru/vkid/latest/vkid/sdk/web/get-started
 */
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

/**
 * Kakao OAuth 2.0.
 *
 * Docs: https://developers.kakao.com/docs/latest/en/kakaologin/rest-api
 */
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

/**
 * Naver OAuth 2.0.
 *
 * Docs: https://developers.naver.com/docs/login/api/api.md
 */
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

/**
 * Hugging Face OAuth 2.0 / OIDC.
 *
 * Docs: https://huggingface.co/docs/hub/en/oauth
 */
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

/**
 * Roblox OAuth 2.0 / OIDC.
 *
 * Docs: https://create.roblox.com/docs/cloud/open-cloud/oauth2-overview
 */
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

/**
 * Vercel OAuth 2.0.
 *
 * Docs: https://vercel.com/docs/integrations/create-integration/submit-integration#oauth2
 */
export function vercelProvider(
	clientId: string,
	clientSecret: string,
	scopes?: string[],
): OAuthProvider {
	return genericOIDC({
		id: "vercel",
		name: "Vercel",
		issuer: "https://vercel.com",
		clientId,
		clientSecret,
		scopes: scopes ?? ["openid", "email", "profile"],
		authorizationUrl: "https://vercel.com/integrations/oauth/authorize",
		tokenUrl: "https://api.vercel.com/v2/oauth/access_token",
		userinfoUrl: "https://api.vercel.com/v2/user",
	});
}

/**
 * Linear OAuth 2.0.
 *
 * Docs: https://developers.linear.app/docs/oauth/authentication
 */
export function linearProvider(
	clientId: string,
	clientSecret: string,
	scopes?: string[],
): OAuthProvider {
	return genericOIDC({
		id: "linear",
		name: "Linear",
		issuer: "https://linear.app",
		clientId,
		clientSecret,
		scopes: scopes ?? ["read"],
		authorizationUrl: "https://linear.app/oauth/authorize",
		tokenUrl: "https://api.linear.app/oauth/token",
		userinfoUrl: "https://api.linear.app/graphql",
	});
}

/**
 * Railway OAuth 2.0.
 *
 * Docs: https://docs.railway.app/reference/public-api#oauth2
 */
export function railwayProvider(
	clientId: string,
	clientSecret: string,
	scopes?: string[],
): OAuthProvider {
	return genericOIDC({
		id: "railway",
		name: "Railway",
		issuer: "https://railway.com",
		clientId,
		clientSecret,
		scopes: scopes ?? ["read:user", "read:project"],
		authorizationUrl: "https://railway.com/oauth/authorize",
		tokenUrl: "https://railway.com/oauth/token",
		userinfoUrl: "https://backboard.railway.com/graphql/v2",
	});
}

/**
 * Kick OAuth 2.0.
 *
 * Docs: https://docs.kick.com/getting-started/authorization-oauth2-flow
 */
export function kickProvider(
	clientId: string,
	clientSecret: string,
	scopes?: string[],
): OAuthProvider {
	return genericOIDC({
		id: "kick",
		name: "Kick",
		issuer: "https://id.kick.com",
		clientId,
		clientSecret,
		scopes: scopes ?? ["user:read"],
		authorizationUrl: "https://id.kick.com/oauth/authorize",
		tokenUrl: "https://id.kick.com/oauth/token",
		userinfoUrl: "https://id.kick.com/oauth/userinfo",
	});
}

/**
 * WeChat OAuth 2.0 (Web Login via QR code).
 *
 * Docs: https://developers.weixin.qq.com/doc/oplatform/en/Website_App/WeChat_Login/Wechat_Login.html
 */
export function wechatProvider(
	clientId: string,
	clientSecret: string,
	scopes?: string[],
): OAuthProvider {
	return genericOIDC({
		id: "wechat",
		name: "WeChat",
		issuer: "https://open.weixin.qq.com",
		clientId,
		clientSecret,
		scopes: scopes ?? ["snsapi_login"],
		authorizationUrl: "https://open.weixin.qq.com/connect/qrconnect",
		tokenUrl: "https://api.weixin.qq.com/sns/oauth2/access_token",
		userinfoUrl: "https://api.weixin.qq.com/sns/userinfo",
	});
}

/**
 * Polar OAuth 2.0 / OIDC.
 *
 * Docs: https://docs.polar.sh/api-reference/oauth2
 */
export function polarProvider(
	clientId: string,
	clientSecret: string,
	scopes?: string[],
): OAuthProvider {
	return genericOIDC({
		id: "polar",
		name: "Polar",
		issuer: "https://polar.sh",
		clientId,
		clientSecret,
		scopes: scopes ?? ["openid", "email", "profile"],
		authorizationUrl: "https://polar.sh/oauth2/authorize",
		tokenUrl: "https://api.polar.sh/v1/oauth2/token",
		userinfoUrl: "https://api.polar.sh/v1/oauth2/userinfo",
	});
}

// ---------------------------------------------------------------------------
// OIDC-discovery providers (tenant/domain required)
// ---------------------------------------------------------------------------

/**
 * Auth0 OIDC provider.
 *
 * Requires the Auth0 tenant domain (e.g. `"dev-abc123.us.auth0.com"`).
 *
 * Docs: https://auth0.com/docs/authenticate/protocols/openid-connect-protocol
 *
 * @example
 * ```typescript
 * const auth0 = auth0Provider("dev-abc123.us.auth0.com", clientId, clientSecret);
 * ```
 */
export function auth0Provider(
	domain: string,
	clientId: string,
	clientSecret: string,
	scopes?: string[],
): OAuthProvider {
	const issuer = `https://${domain.replace(/^https?:\/\//, "")}`;
	return genericOIDC({
		id: "auth0",
		name: "Auth0",
		issuer,
		clientId,
		clientSecret,
		scopes,
	});
}

/**
 * Okta OIDC provider.
 *
 * Requires the Okta domain (e.g. `"dev-12345678.okta.com"`).
 *
 * Docs: https://developer.okta.com/docs/guides/implement-grant-type/authcode/main/
 *
 * @example
 * ```typescript
 * const okta = oktaProvider("dev-12345678.okta.com", clientId, clientSecret);
 * ```
 */
export function oktaProvider(
	domain: string,
	clientId: string,
	clientSecret: string,
	scopes?: string[],
): OAuthProvider {
	const issuer = `https://${domain.replace(/^https?:\/\//, "")}/oauth2/default`;
	return genericOIDC({
		id: "okta",
		name: "Okta",
		issuer,
		clientId,
		clientSecret,
		scopes,
	});
}

/**
 * AWS Cognito OIDC provider.
 *
 * Requires the Cognito hosted UI domain (e.g. `"my-app.auth.us-east-1.amazoncognito.com"`).
 *
 * Docs: https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-userpools-server-contract-reference.html
 *
 * @example
 * ```typescript
 * const cognito = cognitoProvider(
 *   "my-app.auth.us-east-1.amazoncognito.com",
 *   clientId,
 *   clientSecret,
 * );
 * ```
 */
export function cognitoProvider(
	domain: string,
	clientId: string,
	clientSecret: string,
	scopes?: string[],
): OAuthProvider {
	const host = domain.replace(/^https?:\/\//, "").replace(/\/$/, "");
	const issuer = `https://${host}`;
	return genericOIDC({
		id: "cognito",
		name: "AWS Cognito",
		issuer,
		clientId,
		clientSecret,
		scopes: scopes ?? ["openid", "email", "profile"],
		authorizationUrl: `${issuer}/oauth2/authorize`,
		tokenUrl: `${issuer}/oauth2/token`,
		userinfoUrl: `${issuer}/oauth2/userInfo`,
	});
}

// ---------------------------------------------------------------------------
// Self-hosted and identity-platform providers (discovery)
// ---------------------------------------------------------------------------

function trimUrl(url: string): string {
	return url.replace(/\/+$/, "");
}

function str(value: unknown): string | undefined {
	return typeof value === "string" && value.length > 0 ? value : undefined;
}

/**
 * Keycloak OIDC provider.
 *
 * @param baseUrl Keycloak origin, e.g. `https://sso.example.com` (add `/auth` for legacy servers).
 * @param realm Realm name.
 */
export function keycloakProvider(
	baseUrl: string,
	realm: string,
	clientId: string,
	clientSecret: string,
	scopes?: string[],
): OAuthProvider {
	return genericOIDC({
		id: "keycloak",
		name: "Keycloak",
		issuer: `${trimUrl(baseUrl)}/realms/${encodeURIComponent(realm)}`,
		clientId,
		clientSecret,
		scopes,
	});
}

/**
 * Authentik OIDC provider.
 *
 * @param baseUrl Authentik origin, e.g. `https://auth.example.com`.
 * @param slug Application slug from the provider settings.
 */
export function authentikProvider(
	baseUrl: string,
	slug: string,
	clientId: string,
	clientSecret: string,
	scopes?: string[],
): OAuthProvider {
	return genericOIDC({
		id: "authentik",
		name: "Authentik",
		issuer: `${trimUrl(baseUrl)}/application/o/${encodeURIComponent(slug)}`,
		clientId,
		clientSecret,
		scopes,
	});
}

/**
 * ZITADEL OIDC provider.
 *
 * @param domain Instance domain, e.g. `my-instance.zitadel.cloud`.
 */
export function zitadelProvider(
	domain: string,
	clientId: string,
	clientSecret: string,
	scopes?: string[],
): OAuthProvider {
	return genericOIDC({
		id: "zitadel",
		name: "ZITADEL",
		issuer: `https://${domain.replace(/^https?:\/\//, "").replace(/\/+$/, "")}`,
		clientId,
		clientSecret,
		scopes,
	});
}

/**
 * OneLogin OIDC provider.
 *
 * @param subdomain Account subdomain, e.g. `acme` for `acme.onelogin.com`.
 */
export function oneloginProvider(
	subdomain: string,
	clientId: string,
	clientSecret: string,
	scopes?: string[],
): OAuthProvider {
	return genericOIDC({
		id: "onelogin",
		name: "OneLogin",
		issuer: `https://${subdomain}.onelogin.com/oidc/2`,
		clientId,
		clientSecret,
		scopes,
	});
}

/**
 * Gitea / Forgejo OAuth 2.0 provider (self-hosted or gitea.com).
 *
 * @param baseUrl Instance origin, e.g. `https://gitea.com`.
 */
export function giteaProvider(
	baseUrl: string,
	clientId: string,
	clientSecret: string,
	scopes?: string[],
): OAuthProvider {
	const base = trimUrl(baseUrl);
	return genericOIDC({
		id: "gitea",
		name: "Gitea",
		issuer: base,
		clientId,
		clientSecret,
		scopes: scopes ?? ["openid", "email", "profile"],
		authorizationUrl: `${base}/login/oauth/authorize`,
		tokenUrl: `${base}/login/oauth/access_token`,
		userinfoUrl: `${base}/login/oauth/userinfo`,
	});
}

// ---------------------------------------------------------------------------
// Providers with non-OIDC userinfo (use mapProfile)
// ---------------------------------------------------------------------------

/**
 * Patreon OAuth 2.0 (API v2 identity endpoint).
 *
 * Docs: https://docs.patreon.com/#oauth
 */
export function patreonProvider(
	clientId: string,
	clientSecret: string,
	scopes?: string[],
): OAuthProvider {
	return genericOIDC({
		id: "patreon",
		name: "Patreon",
		issuer: "https://www.patreon.com",
		clientId,
		clientSecret,
		scopes: scopes ?? ["identity", "identity[email]"],
		authorizationUrl: "https://www.patreon.com/oauth2/authorize",
		tokenUrl: "https://www.patreon.com/api/oauth2/token",
		userinfoUrl:
			"https://www.patreon.com/api/oauth2/v2/identity?fields%5Buser%5D=email,full_name,image_url",
		mapProfile: (raw) => {
			const data = raw.data as { id?: unknown; attributes?: Record<string, unknown> } | undefined;
			const id = str(data?.id);
			const email = str(data?.attributes?.email);
			if (!id || !email) return null;
			return {
				id,
				email,
				name: str(data?.attributes?.full_name),
				avatar: str(data?.attributes?.image_url),
			};
		},
	});
}

/**
 * Box OAuth 2.0.
 *
 * Docs: https://developer.box.com/guides/authentication/oauth2/
 */
export function boxProvider(
	clientId: string,
	clientSecret: string,
	scopes?: string[],
): OAuthProvider {
	return genericOIDC({
		id: "box",
		name: "Box",
		issuer: "https://account.box.com",
		clientId,
		clientSecret,
		scopes: scopes ?? ["root_readonly"],
		authorizationUrl: "https://account.box.com/api/oauth2/authorize",
		tokenUrl: "https://api.box.com/oauth2/token",
		userinfoUrl: "https://api.box.com/2.0/users/me",
		mapProfile: (raw) => {
			const id = str(raw.id);
			const email = str(raw.login);
			if (!id || !email) return null;
			return { id, email, name: str(raw.name), avatar: str(raw.avatar_url) };
		},
	});
}

/**
 * Yandex ID OAuth 2.0. The userinfo call uses the `OAuth` scheme, not `Bearer`.
 *
 * Docs: https://yandex.com/dev/id/doc/en/codes/code-url
 */
export function yandexProvider(
	clientId: string,
	clientSecret: string,
	scopes?: string[],
): OAuthProvider {
	return genericOIDC({
		id: "yandex",
		name: "Yandex",
		issuer: "https://oauth.yandex.com",
		clientId,
		clientSecret,
		scopes: scopes ?? ["login:email", "login:info"],
		authorizationUrl: "https://oauth.yandex.com/authorize",
		tokenUrl: "https://oauth.yandex.com/token",
		userinfoUrl: "https://login.yandex.ru/info?format=json",
		userinfoAuthScheme: "OAuth",
		mapProfile: (raw) => {
			const id = str(raw.id);
			const email = str(raw.default_email);
			if (!id || !email) return null;
			const avatarId = str(raw.default_avatar_id);
			return {
				id,
				email,
				name: str(raw.real_name) ?? str(raw.display_name),
				avatar: avatarId
					? `https://avatars.yandex.net/get-yapic/${avatarId}/islands-200`
					: undefined,
			};
		},
	});
}

/**
 * WordPress.com OAuth 2.0.
 *
 * Docs: https://developer.wordpress.com/docs/oauth2/
 */
export function wordpressProvider(
	clientId: string,
	clientSecret: string,
	scopes?: string[],
): OAuthProvider {
	return genericOIDC({
		id: "wordpress",
		name: "WordPress.com",
		issuer: "https://public-api.wordpress.com",
		clientId,
		clientSecret,
		scopes: scopes ?? ["auth"],
		authorizationUrl: "https://public-api.wordpress.com/oauth2/authorize",
		tokenUrl: "https://public-api.wordpress.com/oauth2/token",
		userinfoUrl: "https://public-api.wordpress.com/rest/v1/me",
		mapProfile: (raw) => {
			const id = raw.ID !== undefined ? String(raw.ID) : undefined;
			const email = str(raw.email);
			if (!id || !email) return null;
			return { id, email, name: str(raw.display_name), avatar: str(raw.avatar_URL) };
		},
	});
}
