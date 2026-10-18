/**
 * OpenID Connect provider: turns TheAuth into an identity provider for external applications.
 *
 * @example
 * ```typescript
 * import { generateKeyPair } from 'jose';
 * import { createOidcProviderModule } from '@glinr/theauth/auth';
 *
 * const { privateKey } = await generateKeyPair('RS256');
 * const oidc = createOidcProviderModule(
 *   {
 *     issuer: 'https://auth.example.com',
 *     signingKey: privateKey,
 *   },
 *   db,
 *   getUserClaims,
 * );
 *
 * // Register a client
 * const client = await oidc.registerClient({
 *   clientName: 'My App',
 *   redirectUris: ['https://app.example.com/callback'],
 * });
 *
 * // Discovery
 * const doc = oidc.getDiscoveryDocument();
 * ```
 */

import * as jose from "jose";
import type { Database } from "../db/database.js";
import type { AuthError, Result, TheAuthError } from "../mcp/types.js";
import type { OidcLogoutModule, OidcSidIndex } from "./oidc-logout.js";
import { createOidcLogoutModule, createOidcSidIndex } from "./oidc-logout.js";
import { createOidcClients } from "./oidc-provider-clients.js";
import { createOidcDiscovery } from "./oidc-provider-discovery.js";
import {
	DEFAULT_ACCESS_TOKEN_TTL,
	DEFAULT_AUTH_CODE_TTL,
	DEFAULT_ID_TOKEN_TTL,
	DEFAULT_REFRESH_TOKEN_TTL,
	DEFAULT_SCOPES,
	DEFAULT_SIGNING_ALG,
} from "./oidc-provider-helpers.js";
import { createOidcKeys } from "./oidc-provider-keys.js";
import { createOidcTokens } from "./oidc-provider-tokens.js";
import type {
	GetUserClaimsFn,
	OidcProviderConfig,
	OidcProviderContext,
	OidcProviderModule,
} from "./oidc-provider-types.js";

export type {
	AccessTokenClaims,
	AuthorizeParams,
	GetUserClaimsFn,
	JsonWebKeySet,
	OidcClient,
	OidcDiscoveryDocument,
	OidcProviderConfig,
	OidcProviderModule,
	RegisterClientInput,
	TokenParams,
	TokenResponse,
	UserInfoClaims,
} from "./oidc-provider-types.js";
export type { AuthError, Result, TheAuthError };

/** Creates an OIDC provider module that turns TheAuth into an identity provider. */
export function createOidcProviderModule(
	config: OidcProviderConfig,
	db: Database,
	getUserClaims: GetUserClaimsFn,
): OidcProviderModule {
	const issuer = config.issuer;
	const signingAlg = config.signingAlgorithm ?? DEFAULT_SIGNING_ALG;
	const accessTokenTtl = config.accessTokenTtl ?? DEFAULT_ACCESS_TOKEN_TTL;
	const refreshTokenTtl = config.refreshTokenTtl ?? DEFAULT_REFRESH_TOKEN_TTL;
	const authCodeTtl = config.authCodeTtl ?? DEFAULT_AUTH_CODE_TTL;
	const idTokenTtl = config.idTokenTtl ?? DEFAULT_ID_TOKEN_TTL;
	const supportedScopes = config.supportedScopes ?? DEFAULT_SCOPES;

	const keys = createOidcKeys({ config, signingAlg });
	const { getSigningKey, getPublicJwk } = keys;

	const logout: OidcLogoutModule | undefined = config.logout
		? createOidcLogoutModule({
				db,
				issuer,
				signingAlg,
				kid: "theauth-oidc-1",
				getSigningKey,
				getPublicJwk,
				importPublicKey: async (jwk) => {
					const key = await jose.importJWK(jwk, signingAlg);
					return key;
				},
				config: config.logout,
			})
		: undefined;
	const sidIndex: OidcSidIndex | undefined = config.logout
		? createOidcSidIndex(db, issuer, config.logout.indexTtlSeconds)
		: undefined;

	const ctx: OidcProviderContext = {
		config,
		db,
		getUserClaims,
		issuer,
		signingAlg,
		accessTokenTtl,
		refreshTokenTtl,
		authCodeTtl,
		idTokenTtl,
		supportedScopes,
		logout,
		sidIndex,
	};
	const clients = createOidcClients(ctx);
	const discovery = createOidcDiscovery({ ...ctx, getPublicJwk });
	const tokens = createOidcTokens({
		...ctx,
		getSigningKey,
		validateAccessToken: discovery.validateAccessToken,
	});

	return {
		...clients,
		...tokens,
		...discovery,
		...(logout && { logout }),
	};
}
