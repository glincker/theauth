import { trimTrailingSlashes } from "../../../trim-slashes.js";
import type { OAuthProvider } from "../types.js";
import { genericOIDC } from "./generic.js";
import { str, trimUrl } from "./presets-helpers.js";

/** Developer platform, enterprise SSO and OIDC preset providers (Vercel onward). */

/** Vercel OAuth 2.0. Docs: https://vercel.com/docs/integrations/create-integration/submit-integration#oauth2 */
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

/** Linear OAuth 2.0. Docs: https://developers.linear.app/docs/oauth/authentication */
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

/** Railway OAuth 2.0. Docs: https://docs.railway.app/reference/public-api#oauth2 */
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

/** Kick OAuth 2.0. Docs: https://docs.kick.com/getting-started/authorization-oauth2-flow */
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

/** WeChat OAuth 2.0 (Web Login via QR code). Docs: https://developers.weixin.qq.com/doc/oplatform/en/Website_App/WeChat_Login/Wechat_Login.html */
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

/** Polar OAuth 2.0 / OIDC. Docs: https://docs.polar.sh/api-reference/oauth2 */
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

/**
 * Auth0 OIDC provider. Pass the tenant domain, e.g. `dev-abc123.us.auth0.com`. Docs: https://auth0.com/docs/authenticate/protocols/openid-connect-protocol
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
 * Okta OIDC provider. Pass the Okta domain, e.g. `dev-12345678.okta.com`. Docs: https://developer.okta.com/docs/guides/implement-grant-type/authcode/main/
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
 * AWS Cognito OIDC provider. Pass the hosted UI domain, e.g. `my-app.auth.us-east-1.amazoncognito.com`. Docs: https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-userpools-server-contract-reference.html
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

/** Keycloak OIDC provider. `baseUrl` is the origin, e.g. `https://sso.example.com` (add `/auth` for legacy servers). */
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

/** Authentik OIDC provider. `baseUrl` is the origin, e.g. `https://auth.example.com`. `slug` is the application slug. */
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

/** ZITADEL OIDC provider. `domain` is the instance domain, e.g. `my-instance.zitadel.cloud`. */
export function zitadelProvider(
	domain: string,
	clientId: string,
	clientSecret: string,
	scopes?: string[],
): OAuthProvider {
	return genericOIDC({
		id: "zitadel",
		name: "ZITADEL",
		issuer: `https://${trimTrailingSlashes(domain.replace(/^https?:\/\//, ""))}`,
		clientId,
		clientSecret,
		scopes,
	});
}

/** OneLogin OIDC provider. `subdomain` is the account subdomain, e.g. `acme` for `acme.onelogin.com`. */
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

/** Gitea / Forgejo OAuth 2.0 provider (self-hosted or gitea.com). `baseUrl` is the instance origin, e.g. `https://gitea.com`. */
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

/** Patreon OAuth 2.0 (API v2 identity endpoint). Docs: https://docs.patreon.com/#oauth */
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

/** Box OAuth 2.0. Docs: https://developer.box.com/guides/authentication/oauth2/ */
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

/** Yandex ID OAuth 2.0. The userinfo call uses the `OAuth` scheme, not `Bearer`. Docs: https://yandex.com/dev/id/doc/en/codes/code-url */
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

/** WordPress.com OAuth 2.0. Docs: https://developer.wordpress.com/docs/oauth2/ */
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
