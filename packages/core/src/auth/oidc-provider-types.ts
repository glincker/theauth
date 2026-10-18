import type * as jose from "jose";
import type { Database } from "../db/database.js";
import type { Result } from "../mcp/types.js";
import type { OidcLogoutConfig, OidcLogoutModule, OidcSidIndex } from "./oidc-logout.js";

export interface OidcProviderConfig {
	/** Issuer identifier, e.g. "https://auth.example.com". Must be a URL. */
	issuer: string;
	/** Private key used to sign ID tokens and access tokens (RSA or EC). */
	signingKey: CryptoKey | jose.JWK;
	/** JWT signing algorithm. Default: 'RS256'. */
	signingAlgorithm?: string;
	/** Access token lifetime in seconds. Default: 3600 (1 hour). */
	accessTokenTtl?: number;
	/** Refresh token lifetime in seconds. Default: 2592000 (30 days). */
	refreshTokenTtl?: number;
	/** Authorization code lifetime in seconds. Default: 600 (10 minutes). */
	authCodeTtl?: number;
	/** ID token lifetime in seconds. Default: 3600 (1 hour). */
	idTokenTtl?: number;
	/** Scopes this provider supports. Default: ['openid', 'profile', 'email']. */
	supportedScopes?: string[];
	/** Opt in to RP-initiated logout and back-channel logout fan-out. Adds the logout fields to discovery. */
	logout?: OidcLogoutConfig;
}

export interface RegisterClientInput {
	clientName: string;
	redirectUris: string[];
	grantTypes?: string[];
	responseTypes?: string[];
	scopes?: string[];
	tokenEndpointAuthMethod?: string;
	/** Allowlist for `post_logout_redirect_uri` (needs `config.logout`). */
	postLogoutRedirectUris?: string[];
	/** Client endpoint that receives back-channel logout tokens (needs `config.logout`). */
	backchannelLogoutUri?: string;
}

export interface OidcClient {
	clientId: string;
	clientSecret: string | null;
	clientName: string;
	redirectUris: string[];
	grantTypes: string[];
	responseTypes: string[];
	scopes: string[];
	tokenEndpointAuthMethod: string;
	createdAt: Date;
}

export interface AuthorizeParams {
	clientId: string;
	redirectUri: string;
	responseType: string;
	scope: string;
	state?: string;
	nonce?: string;
	codeChallenge?: string;
	codeChallengeMethod?: string;
	/** The authenticated user's ID. Must be resolved before calling authorize. */
	userId: string;
	/** Provider session id of the signed-in user. With `config.logout` it is indexed so session revoke and logout can notify this client. */
	sessionId?: string;
}

export interface TokenParams {
	grantType: string;
	code?: string;
	redirectUri?: string;
	codeVerifier?: string;
	refreshToken?: string;
	clientId: string;
	clientSecret?: string;
}

export interface TokenResponse {
	accessToken: string;
	idToken: string;
	refreshToken: string;
	tokenType: "Bearer";
	expiresIn: number;
}

export interface UserInfoClaims {
	sub: string;
	email?: string;
	name?: string;
	picture?: string;
	emailVerified?: boolean;
}

export interface AccessTokenClaims {
	sub: string;
	iss: string;
	aud: string;
	exp: number;
	iat: number;
	jti: string;
	scope: string;
	clientId: string;
}

export interface OidcDiscoveryDocument {
	issuer: string;
	authorization_endpoint: string;
	token_endpoint: string;
	userinfo_endpoint: string;
	jwks_uri: string;
	registration_endpoint: string;
	scopes_supported: string[];
	response_types_supported: string[];
	grant_types_supported: string[];
	subject_types_supported: string[];
	id_token_signing_alg_values_supported: string[];
	token_endpoint_auth_methods_supported: string[];
	claims_supported: string[];
	code_challenge_methods_supported: string[];
	end_session_endpoint?: string;
	backchannel_logout_supported?: boolean;
	backchannel_logout_session_supported?: boolean;
}

export interface JsonWebKeySet {
	keys: jose.JWK[];
}

/** Callback to resolve user claims for ID tokens and the userinfo endpoint. */
export type GetUserClaimsFn = (userId: string, scopes: string[]) => Promise<UserInfoClaims>;

export interface OidcProviderModule {
	registerClient(input: RegisterClientInput): Promise<Result<OidcClient>>;
	getClient(clientId: string): Promise<Result<OidcClient>>;
	deleteClient(clientId: string): Promise<Result<void>>;
	authorize(params: AuthorizeParams): Promise<Result<{ code: string; state?: string }>>;
	exchangeToken(params: TokenParams): Promise<Result<TokenResponse>>;
	getUserInfo(accessToken: string): Promise<Result<UserInfoClaims>>;
	getDiscoveryDocument(): OidcDiscoveryDocument;
	getJwks(): Promise<JsonWebKeySet>;
	validateAccessToken(token: string): Promise<Result<AccessTokenClaims>>;
	/** Present when `config.logout` was provided. */
	logout?: OidcLogoutModule;
}

/** Shared configuration, store and key accessors passed to the OIDC provider sub-modules. */
export interface OidcProviderContext {
	config: OidcProviderConfig;
	db: Database;
	getUserClaims: GetUserClaimsFn;
	issuer: string;
	signingAlg: string;
	accessTokenTtl: number;
	refreshTokenTtl: number;
	authCodeTtl: number;
	idTokenTtl: number;
	supportedScopes: string[];
	logout: OidcLogoutModule | undefined;
	sidIndex: OidcSidIndex | undefined;
}
