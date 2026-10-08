/**
 * Generic OIDC provider factory.
 *
 * Builds a fully functional OAuthProvider from a minimal config. When an
 * OIDC issuer URL is supplied the factory constructs the standard
 * `/.well-known/openid-configuration` discovery URL. Explicit endpoint
 * overrides take precedence over discovery, so the factory works with
 * providers that do not implement RFC 8414.
 *
 * Spec references:
 * - OIDC Discovery: https://openid.net/specs/openid-connect-discovery-1_0.html
 * - RFC 8414 (OAuth 2.0 Authorization Server Metadata)
 */

import { deriveCodeChallenge } from "../pkce.js";
import type { OAuthProvider, OAuthTokens, OAuthUserInfo } from "../types.js";

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

export interface GenericOIDCConfig {
	/** Machine-readable provider ID, e.g. `'okta'`, `'auth0'`. */
	id: string;
	/** Human-readable display name, e.g. `'Okta'`. */
	name: string;
	/**
	 * OIDC issuer URL. Used to derive the discovery document URL as
	 * `${issuer}/.well-known/openid-configuration` when explicit endpoint
	 * overrides are not provided.
	 *
	 * @example "https://dev-12345678.okta.com"
	 */
	issuer: string;
	/** OAuth application client ID. */
	clientId: string;
	/** OAuth application client secret. */
	clientSecret: string;
	/**
	 * Scopes to request. Defaults to `['openid', 'email', 'profile']`.
	 */
	scopes?: string[];
	/**
	 * Override the redirect URI registered with the provider.
	 * When omitted the URI passed at call time is used.
	 */
	redirectUri?: string;
	// --- Optional endpoint overrides (skip discovery) ---
	/** Authorization endpoint. Overrides discovery. */
	authorizationUrl?: string;
	/** Token endpoint. Overrides discovery. */
	tokenUrl?: string;
	/** UserInfo endpoint. Overrides discovery. */
	userinfoUrl?: string;
	/**
	 * Map a non-OIDC userinfo response to a profile. Use for providers whose
	 * userinfo has no `sub` or nests the profile. Return null when the response
	 * is unusable. When omitted the standard OIDC claims are read.
	 */
	mapProfile?: (raw: Record<string, unknown>) => {
		id: string;
		email: string;
		name?: string;
		avatar?: string;
	} | null;
	/** Authorization scheme for the userinfo request (default `Bearer`). */
	userinfoAuthScheme?: string;
}

// ---------------------------------------------------------------------------
// Discovery cache — one entry per issuer, populated lazily at first use
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Raw response shapes
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/**
 * Create an OAuthProvider backed by a standard OIDC issuer.
 *
 * Endpoints are resolved from the issuer's discovery document on first use
 * and cached in memory for the lifetime of the process. Pass explicit
 * `authorizationUrl`, `tokenUrl`, and `userinfoUrl` to bypass discovery.
 *
 * @example
 * ```typescript
 * const okta = genericOIDC({
 *   id: "okta",
 *   name: "Okta",
 *   issuer: "https://dev-12345678.okta.com",
 *   clientId: process.env.OKTA_CLIENT_ID,
 *   clientSecret: process.env.OKTA_CLIENT_SECRET,
 * });
 * ```
 */
export function genericOIDC(config: GenericOIDCConfig): OAuthProvider {
	const defaultScopes = ["openid", "email", "profile"];
	const scopes = mergeScopes(defaultScopes, config.scopes);

	/** Resolve endpoints: use explicit overrides first, then discover. */
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
		const codeChallenge = await deriveCodeChallenge(codeVerifier);
		const effectiveRedirectUri = config.redirectUri ?? redirectUri;

		const params = new URLSearchParams({
			client_id: config.clientId,
			redirect_uri: effectiveRedirectUri,
			response_type: "code",
			scope: scopes.join(" "),
			state,
			code_challenge: codeChallenge,
			code_challenge_method: "S256",
		});

		return `${endpoints.authorizationUrl}?${params.toString()}`;
	}

	async function exchangeCode(
		code: string,
		codeVerifier: string,
		redirectUri: string,
	): Promise<OAuthTokens> {
		const endpoints = await resolveEndpoints();
		const effectiveRedirectUri = config.redirectUri ?? redirectUri;

		const body = new URLSearchParams({
			grant_type: "authorization_code",
			client_id: config.clientId,
			client_secret: config.clientSecret,
			code,
			code_verifier: codeVerifier,
			redirect_uri: effectiveRedirectUri,
		});

		const response = await fetch(endpoints.tokenUrl, {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
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

		const response = await fetch(endpoints.userinfoUrl, {
			headers: { Authorization: `${config.userinfoAuthScheme ?? "Bearer"} ${accessToken}` },
		});

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
			return { id: mapped.id, email: mapped.email, name: mapped.name, avatar: mapped.avatar, raw };
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
		getUserInfo,
	};
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function mergeScopes(defaults: string[], extras?: string[]): string[] {
	if (!extras || extras.length === 0) return defaults;
	return [...new Set([...defaults, ...extras])];
}
