/** Generic OIDC provider factory: builds an OAuthProvider from a minimal config and an issuer. */

import { deriveCodeChallenge } from "../pkce.js";
import type { OAuthProvider, OAuthTokens, OAuthUserInfo } from "../types.js";
import { createRefresher } from "./refresh.js";

export interface GenericOIDCConfig {
	id: string;
	name: string;
	/**
	 * OIDC issuer URL. Used to derive the discovery document URL as `${issuer}/.well-known/openid-configuration` when explicit endpoint overrides are not provided.
	 *
	 * @example "https://dev-12345678.okta.com"
	 */
	issuer: string;
	clientId: string;
	clientSecret: string;
	/** Scopes to request. Default: `['openid', 'email', 'profile']`. */
	scopes?: string[];
	/** Replaces the built-in `['openid', 'email', 'profile']` baseline that `scopes` is merged into. Use it for providers that reject or do not define the OIDC scopes. */
	defaultScopes?: string[];
	/** Override the redirect URI registered with the provider. Defaults to the URI passed at call time. */
	redirectUri?: string;
	authorizationUrl?: string;
	tokenUrl?: string;
	userinfoUrl?: string;
	/** Maps a non-OIDC userinfo response to a profile. Use it for providers whose userinfo has no `sub`. */
	mapProfile?: (raw: Record<string, unknown>) => {
		id: string;
		email: string;
		name?: string;
		avatar?: string;
		/** Set only when the provider states the email is verified. */
		emailVerified?: boolean;
	} | null;
	/** Authorization scheme for the userinfo request (default `Bearer`). */
	userinfoAuthScheme?: string;
	/** Separator used to join scopes in the authorize URL (default a space). */
	scopeSeparator?: string;
	/** HTTP method for the userinfo request (default `GET`). */
	userinfoMethod?: "GET" | "POST";
	/** Request body for the userinfo call, sent as `application/json`. Use it for GraphQL endpoints. Only meaningful with `userinfoMethod: "POST"`. */
	userinfoBody?: string;
	authorizationParams?: Record<string, string>;
	/** How client credentials reach the token endpoint: in the form body (default) or in an `Authorization: Basic` header. Applies to refresh too. */
	tokenAuth?: "body" | "basic";
	/** Send the PKCE challenge and verifier (default `true`). Set `false` for providers whose documentation does not describe PKCE. */
	pkce?: boolean;
}

// One discovery entry per issuer, populated lazily at first use.

interface DiscoveredEndpoints {
	authorizationUrl: string;
	tokenUrl: string;
	userinfoUrl: string;
}

const discoveryCache = new Map<string, DiscoveredEndpoints>();

async function discoverEndpoints(issuer: string): Promise<DiscoveredEndpoints> {
	const cached = discoveryCache.get(issuer);
	if (cached) return cached;

	const url = `${issuer.replace(/\/$/, "")}/.well-known/openid-configuration`;
	const response = await fetch(url);

	if (!response.ok) {
		throw new Error(
			`OIDC discovery failed for issuer "${issuer}" (${response.status}). ` +
				"Provide explicit authorizationUrl / tokenUrl / userinfoUrl to skip discovery.",
		);
	}

	const doc = (await response.json()) as Record<string, unknown>;

	const authorizationUrl = assertString(
		doc.authorization_endpoint,
		"authorization_endpoint",
		issuer,
	);
	const tokenUrl = assertString(doc.token_endpoint, "token_endpoint", issuer);
	const userinfoUrl = assertString(doc.userinfo_endpoint, "userinfo_endpoint", issuer);

	const endpoints: DiscoveredEndpoints = { authorizationUrl, tokenUrl, userinfoUrl };
	discoveryCache.set(issuer, endpoints);
	return endpoints;
}

function assertString(value: unknown, field: string, issuer: string): string {
	if (typeof value !== "string" || value.length === 0) {
		throw new Error(`OIDC discovery for "${issuer}" returned no "${field}" field.`);
	}
	return value;
}

interface OIDCTokenResponse {
	access_token: string;
	refresh_token?: string;
	expires_in?: number;
	token_type?: string;
	id_token?: string;
}

interface OIDCUserInfoResponse {
	sub: string;
	email?: string;
	email_verified?: boolean;
	name?: string;
	picture?: string;
	[key: string]: unknown;
}

/** Creates an OAuthProvider backed by a standard OIDC issuer. Endpoints are resolved on first use. */
export function genericOIDC(config: GenericOIDCConfig): OAuthProvider {
	const defaultScopes = config.defaultScopes ?? ["openid", "email", "profile"];
	const scopes = mergeScopes(defaultScopes, config.scopes);

	async function resolveEndpoints(): Promise<DiscoveredEndpoints> {
		if (config.authorizationUrl && config.tokenUrl && config.userinfoUrl) {
			return {
				authorizationUrl: config.authorizationUrl,
				tokenUrl: config.tokenUrl,
				userinfoUrl: config.userinfoUrl,
			};
		}
		const discovered = await discoverEndpoints(config.issuer);
		return {
			authorizationUrl: config.authorizationUrl ?? discovered.authorizationUrl,
			tokenUrl: config.tokenUrl ?? discovered.tokenUrl,
			userinfoUrl: config.userinfoUrl ?? discovered.userinfoUrl,
		};
	}

	async function getAuthorizationUrl(
		state: string,
		codeVerifier: string,
		redirectUri: string,
	): Promise<string> {
		const endpoints = await resolveEndpoints();
		const effectiveRedirectUri = config.redirectUri ?? redirectUri;

		const params = new URLSearchParams({
			client_id: config.clientId,
			redirect_uri: effectiveRedirectUri,
			response_type: "code",
			scope: scopes.join(config.scopeSeparator ?? " "),
			state,
		});
		if (config.pkce !== false) {
			params.set("code_challenge", await deriveCodeChallenge(codeVerifier));
			params.set("code_challenge_method", "S256");
		}
		for (const [key, value] of Object.entries(config.authorizationParams ?? {})) {
			params.set(key, value);
		}

		return `${endpoints.authorizationUrl}?${params.toString()}`;
	}

	async function exchangeCode(
		code: string,
		codeVerifier: string,
		redirectUri: string,
	): Promise<OAuthTokens> {
		const endpoints = await resolveEndpoints();
		const effectiveRedirectUri = config.redirectUri ?? redirectUri;

		const basic = config.tokenAuth === "basic";
		const body = new URLSearchParams({
			grant_type: "authorization_code",
			code,
			redirect_uri: effectiveRedirectUri,
		});
		if (config.pkce !== false) body.set("code_verifier", codeVerifier);
		const headers: Record<string, string> = {
			"Content-Type": "application/x-www-form-urlencoded",
		};
		if (basic) {
			headers.Authorization = `Basic ${btoa(`${config.clientId}:${config.clientSecret}`)}`;
		} else {
			body.set("client_id", config.clientId);
			body.set("client_secret", config.clientSecret);
		}

		const response = await fetch(endpoints.tokenUrl, {
			method: "POST",
			headers,
			body: body.toString(),
		});

		if (!response.ok) {
			const text = await response.text();
			throw new Error(`${config.name} token exchange failed (${response.status}): ${text}`);
		}

		const raw = (await response.json()) as Record<string, unknown>;
		const data = raw as unknown as OIDCTokenResponse;

		return {
			accessToken: data.access_token,
			refreshToken: data.refresh_token,
			expiresIn: data.expires_in,
			tokenType: data.token_type ?? "Bearer",
			raw,
		};
	}

	async function getUserInfo(accessToken: string): Promise<OAuthUserInfo> {
		const endpoints = await resolveEndpoints();

		const headers: Record<string, string> = {
			Authorization: `${config.userinfoAuthScheme ?? "Bearer"} ${accessToken}`,
		};
		const init: RequestInit = { headers };
		if (config.userinfoMethod === "POST") {
			init.method = "POST";
			if (config.userinfoBody !== undefined) {
				headers["Content-Type"] = "application/json";
				init.body = config.userinfoBody;
			}
		}
		const response = await fetch(endpoints.userinfoUrl, init);

		if (!response.ok) {
			const text = await response.text();
			throw new Error(`${config.name} userinfo fetch failed (${response.status}): ${text}`);
		}

		const raw = (await response.json()) as Record<string, unknown>;
		if (config.mapProfile) {
			const mapped = config.mapProfile(raw);
			if (!mapped?.id || !mapped.email) {
				throw new Error(`${config.name} userinfo response missing a usable id or email.`);
			}
			return {
				id: mapped.id,
				email: mapped.email,
				name: mapped.name,
				avatar: mapped.avatar,
				...(mapped.emailVerified === undefined ? {} : { emailVerified: mapped.emailVerified }),
				raw,
			};
		}

		const data = raw as unknown as OIDCUserInfoResponse;

		if (!data.sub) {
			throw new Error(`${config.name} userinfo response missing required "sub" field.`);
		}

		const email = data.email ?? "";
		if (!email) {
			throw new Error(
				`${config.name} userinfo response missing "email". ` +
					"Ensure the 'email' scope is included.",
			);
		}

		return {
			id: data.sub,
			email,
			name: data.name,
			avatar: data.picture,
			raw,
		};
	}

	// Expose static URLs where they are known upfront (overrides only).
	// Discovery-based providers expose the issuer discovery URL instead so
	// callers can always find the authoritative endpoint list.
	const staticAuthUrl =
		config.authorizationUrl ??
		`${config.issuer.replace(/\/$/, "")}/.well-known/openid-configuration`;

	return {
		id: config.id,
		name: config.name,
		authorizationUrl: staticAuthUrl,
		tokenUrl: config.tokenUrl ?? config.issuer,
		userInfoUrl: config.userinfoUrl ?? config.issuer,
		scopes,
		getAuthorizationUrl,
		exchangeCode,
		refreshTokens: async (refreshToken) => {
			const endpoints = await resolveEndpoints();
			return createRefresher({
				providerName: config.name,
				tokenUrl: endpoints.tokenUrl,
				clientId: config.clientId,
				clientSecret: config.clientSecret,
				authStyle: config.tokenAuth === "basic" ? "basic" : "body",
			})(refreshToken);
		},
		getUserInfo,
	};
}

function mergeScopes(defaults: string[], extras?: string[]): string[] {
	if (!extras || extras.length === 0) return defaults;
	return [...new Set([...defaults, ...extras])];
}
