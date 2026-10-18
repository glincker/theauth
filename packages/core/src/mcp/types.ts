import type { JWK } from "jose";
import type { TheAuthLogger } from "../observability/types.js";
import type { SecondaryStorage } from "../storage/types.js";
import type { McpDpopConfig } from "./dpop-types.js";
import type {
	McpClientCredentialsConfig,
	McpJwtBearerConfig,
	McpLenientClientsConfig,
	McpTokenExchangeConfig,
} from "./grant-types.js";
import type { McpProtectedHandler, RequireMcpAuthOptions } from "./require-mcp-auth.js";
import type {
	McpDelegationBinding,
	McpIntrospectionConfig,
	McpIntrospectionResponse,
	McpRevalidate,
	McpRevocationConfig,
	McpSessionFreshness,
} from "./revocation-types.js";
import type {
	McpClientBindings,
	McpRegistrationConfig,
	RequireScopesResult,
} from "./types-auth.js";
import type {
	ClientDescription,
	McpCimdAdmin,
	McpCimdConfig,
	McpClientBlockStore,
	McpClientCimdSnapshot,
} from "./types-cimd.js";

export type { McpValidateOptions } from "./revocation-types.js";

export type {
	McpAuthErrorCode,
	McpClientBindings,
	McpRegistrationConfig,
	McpRejectedToken,
	RequireScopesResult,
} from "./types-auth.js";

export interface TheAuthError {
	code: string;
	message: string;
	details?: Record<string, unknown>;
}

/**
 * @deprecated Use `TheAuthError` instead. Will be removed in a future major version.
 */
export type AuthError = TheAuthError;

export type Result<T> = { success: true; data: T } | { success: false; error: TheAuthError };

export interface McpConfig {
	enabled: boolean;
	enforceAuth?: boolean;
	scopes?: string[];
	issuer?: string;
	baseUrl?: string;
	/** HS256 signing secret (at least 32 chars). Required unless `signing` is set. */
	signingSecret?: string;
	/** Opt in to asymmetric signing (ES256 or EdDSA). Tokens get a `kid` header; public keys are published in the JWKS. */
	signing?: McpSigningConfig;
	/** Canonical URI of this resource server (RFC 8707). */
	resource?: string;
	/** Optional jti denylist. When set, revoked access tokens are refused. */
	jtiDenylist?: McpJtiDenylist;
	/** How resource server validations see revocation (live, cached, offline). Introspection is always live. */
	revocation?: McpRevocationConfig;
	/** RFC 7662 introspection endpoint. Off unless `enabled`. */
	introspection?: McpIntrospectionConfig;
	/** Opt in to a live delegation check: `validateAccessToken` walks the token's `act` chain against this store. */
	delegationStore?: McpDelegationStore;
	/** Maps each actor in the delegation chain (and the token `sub`) to the agent id used in delegation records. */
	resolveActorAgentId?: McpActorAgentResolver;
	/** Lets actors that `resolveActorAgentId` maps to `undefined` keep their raw id instead of failing the chain. */
	allowUnmappedActors?: boolean;
	/** Opt in to DPoP (RFC 9449). The token endpoint accepts a `DPoP` proof and issues `cnf.jkt`-bound tokens. */
	dpop?: McpDpopConfig;
	/** Refresh token family store for rotation and reuse detection. Defaults to an in-process store. */
	tokenFamilies?: McpTokenFamilyStore;
	/** Client ID Metadata Documents (client_id is an https URL). Off by default. */
	clientIdMetadataDocuments?: McpCimdConfig;
	/** Compatibility switches for lenient MCP clients. */
	lenientClients?: McpLenientClientsConfig;
	/** Opt in to the `client_credentials` grant for confidential clients. Requires a `resolvePrincipal` mapping. */
	clientCredentials?: McpClientCredentialsConfig;
	/** Opt in to RFC 8693 token exchange. Requires `jtiDenylist` so revoked subject tokens are refused. */
	tokenExchange?: McpTokenExchangeConfig;
	/** Opt in to RFC 7523 `jwt-bearer` redemption of ID-JAG assertions (`typ: oauth-id-jag+jwt`) from trusted issuers. */
	jwtBearer?: McpJwtBearerConfig;
	/** Replay cache for `private_key_jwt` and jwt-bearer assertions (`jti`). */
	assertionStorage?: SecondaryStorage;
	/** Access token TTL in seconds (default: 3600) */
	accessTokenTtl?: number;
	/** Refresh token TTL in seconds (default: 604800 = 7 days) */
	refreshTokenTtl?: number;
	/** Absolute lifetime of a refresh token family in seconds (default: 2592000, 30 days). Rotation slides the per-token expiry but never extends past this. */
	refreshTokenAbsoluteTtl?: number;
	/** Authorization code TTL in seconds (default: 600 = 10 minutes) */
	codeTtl?: number;
	allowedResources?: string[];
	loginPage?: string;
	consentPage?: string;
	/** Clients pre-registered at startup, stored via `storeClient` when the module initializes. */
	preRegisteredClients?: Array<{
		clientId: string;
		clientSecret?: string;
		redirectUris: string[];
		clientName?: string;
		scope?: string;
		/** Grant types this client may use. Default: authorization_code and refresh_token. */
		grantTypes?: string[];
		/** Agent this client acts as. Tokens issued to the client carry it as `agent_id`. */
		agentId?: string;
	}>;
	/** Dynamic client registration options. */
	registration?: McpRegistrationConfig;
	getAdditionalClaims?: (userId: string, scopes: string[]) => Promise<Record<string, unknown>>;
	/** Emit IETF agentic JWT claims on issued access tokens. */
	emitAgenticJwtClaims?: boolean;
	/** Agentic context for a user at token issuance. Called only when `emitAgenticJwtClaims` is on. */
	getAgenticContext?: (userId: string) => Promise<{
		agentId?: string;
		agentType?: "autonomous" | "delegated" | "supervised";
		trustTier?: "unverified" | "low" | "standard" | "elevated" | "high";
	}>;
}

export type McpAsymmetricAlg = "ES256" | "EdDSA";

export interface McpSigningConfig {
	alg: McpAsymmetricAlg;
	current: { kid: string; privateKey: JWK };
	/** Retired keys that remain published and accepted for verification. */
	previous?: Array<{ kid: string; publicKey: JWK }>;
}

export interface McpJtiDenylist {
	/** Deny a token id until `expiresAt`, after which the entry may be dropped. */
	revoke: (jti: string, expiresAt: Date) => Promise<void>;
	isRevoked: (jti: string) => Promise<boolean>;
}

export interface McpDelegationLink {
	status: "active" | "revoked" | "expired";
	expiresAt: Date;
}

/** An actor in a delegation chain: a hop's `sub` and client id, or the token subject. */
export interface McpActorRef {
	sub: string;
	clientId?: string;
}

/** Maps a chain actor to the agent id used in delegation records. */
export type McpActorAgentResolver = (
	actor: McpActorRef,
) => string | undefined | Promise<string | undefined>;

export interface McpDelegationStore {
	/** Return the link granting `to` authority from `from`, or null when none exists. */
	findLink: (from: string, to: string) => Promise<McpDelegationLink | null>;
}

/** Subset of the session `TokenFamilyStore` that the MCP token endpoint uses. */
export interface McpTokenFamilyStore {
	createFamily: (userId: string, absoluteExpiresAt: Date) => Promise<{ id: string }>;
	issueToken: (familyId: string, ttlMs: number) => Promise<{ rawToken: string; expiresAt: Date }>;
	consumeToken: (rawToken: string) => Promise<{
		status: "ok" | "expired" | "revoked" | "reuse" | "not_found";
		family?: { id: string };
	}>;
	revokeFamily: (familyId: string) => Promise<void>;
}

// OAuth 2.0 Authorization Server Metadata (RFC 8414)

export interface McpServerMetadata {
	issuer: string;
	authorization_endpoint: string;
	token_endpoint: string;
	/** Omitted when `registration.enabled === false`. */
	registration_endpoint?: string;
	jwks_uri?: string;
	scopes_supported: string[];
	response_types_supported: string[];
	response_modes_supported: string[];
	grant_types_supported: string[];
	token_endpoint_auth_methods_supported: string[];
	/** RFC 8414: JWS algorithms accepted for `private_key_jwt` assertions. */
	token_endpoint_auth_signing_alg_values_supported?: string[];
	code_challenge_methods_supported: string[];
	service_documentation?: string;
	revocation_endpoint?: string;
	revocation_endpoint_auth_methods_supported?: string[];
	revocation_endpoint_auth_signing_alg_values_supported?: string[];
	/** RFC 8414 / RFC 7662: present only when introspection is enabled (and the route is mounted). */
	introspection_endpoint?: string;
	introspection_endpoint_auth_methods_supported?: string[];
	introspection_endpoint_auth_signing_alg_values_supported?: string[];
	/** RFC 9207: the authorization response carries an `iss` parameter. */
	authorization_response_iss_parameter_supported?: boolean;
	client_id_metadata_document_supported?: boolean;
	/** RFC 9449 section 5.1: JWS algorithms accepted for DPoP proofs. */
	dpop_signing_alg_values_supported?: string[];
}

// Protected Resource Metadata (RFC 9728)

export interface McpProtectedResourceMetadata {
	resource: string;
	authorization_servers: string[];
	jwks_uri?: string;
	scopes_supported: string[];
	bearer_methods_supported: string[];
	resource_signing_alg_values_supported?: string[];
	/** RFC 9728: JWS algorithms accepted for DPoP proofs. */
	dpop_signing_alg_values_supported?: string[];
	/** RFC 9728: true when this resource refuses tokens that are not DPoP-bound. */
	dpop_bound_access_tokens_required?: boolean;
}

// OAuth Client (RFC 7591 Dynamic Client Registration)

export interface McpClient {
	clientId: string;
	clientSecret: string | null;
	clientName: string | null;
	clientUri: string | null;
	logoUri: string | null;
	redirectUris: string[];
	grantTypes: string[];
	responseTypes: string[];
	tokenEndpointAuthMethod: string;
	scope: string | null;
	contacts: string[] | null;
	tosUri: string | null;
	policyUri: string | null;
	softwareId: string | null;
	softwareVersion: string | null;
	clientType: "public" | "confidential";
	disabled: boolean;
	/** Why the client is disabled, for example "blocked" or "cimd_changed_while_bound". */
	disabledReason?: string | null;
	userId: string | null;
	/** The agent this client acts as, or null/absent when unbound. Tokens issued to the client carry it as `agent_id` and the built-in delegation mapping resolves the client to it. */
	agentId?: string | null;
	/** Set to "cimd" for clients resolved from a Client ID Metadata Document. */
	source?: "cimd";
	jwks?: { keys: JWK[] };
	jwksUri?: string;
	/** Snapshot of the fetched Client ID Metadata Document (source "cimd" only). */
	cimd?: McpClientCimdSnapshot;
	createdAt: Date;
	updatedAt: Date;
}

export interface McpClientRegistrationRequest {
	redirect_uris: string[];
	token_endpoint_auth_method?: string;
	grant_types?: string[];
	response_types?: string[];
	client_name?: string;
	client_uri?: string;
	logo_uri?: string;
	scope?: string;
	contacts?: string[];
	tos_uri?: string;
	policy_uri?: string;
	software_id?: string;
	software_version?: string;
	jwks?: { keys: JWK[] };
	jwks_uri?: string;
}

export interface McpClientRegistrationResponse {
	client_id: string;
	client_secret?: string;
	client_id_issued_at: number;
	client_secret_expires_at?: number;
	redirect_uris: string[];
	token_endpoint_auth_method: string;
	grant_types: string[];
	response_types: string[];
	client_name?: string;
	client_uri?: string;
	logo_uri?: string;
	scope?: string;
	contacts?: string[];
	tos_uri?: string;
	policy_uri?: string;
	software_id?: string;
	software_version?: string;
	jwks?: { keys: JWK[] };
	jwks_uri?: string;
}

export interface McpAuthorizationCode {
	code: string;
	clientId: string;
	userId: string;
	redirectUri: string;
	scope: string[];
	codeChallenge: string;
	codeChallengeMethod: "S256";
	resource: string | null;
	expiresAt: Date;
	createdAt: Date;
}

export interface McpAuthorizeRequest {
	response_type: string;
	client_id: string;
	redirect_uri: string;
	scope?: string;
	state?: string;
	code_challenge: string;
	code_challenge_method: string;
	resource: string;
}

export interface McpAuthorizeResult {
	redirectUri: string;
	code: string;
	state: string | null;
}

/** An access token minted inside a refresh token family. */
export interface McpFamilyAccessTokenRef {
	jti: string;
	expiresAt: Date;
}

export interface McpAccessToken {
	/** SHA-256 hex digest of the access token JWT. The raw token is never handed to storage. Rows written by older versions hold the raw JWT. */
	accessToken: string;
	/** SHA-256 hex digest of the refresh token, or null. Rows written by older versions hold the raw value; lookups fall back to it once. */
	refreshToken: string | null;
	jti?: string;
	/** Refresh token family, used for reuse detection (RFC 9700). */
	familyId?: string;
	tokenType: "Bearer" | "DPoP";
	/** RFC 7638 thumbprint of the DPoP key this grant is bound to. Persist it: the refresh grant refuses any other key. Absent for bearer grants. */
	dpopJkt?: string;
	expiresIn: number;
	scope: string[];
	clientId: string;
	userId: string;
	resource: string | null;
	expiresAt: Date;
	createdAt: Date;
}

export interface McpTokenRequest {
	grant_type: string;
	code?: string;
	redirect_uri?: string;
	client_id?: string;
	client_secret?: string;
	code_verifier?: string;
	refresh_token?: string;
	resource?: string;
	scope?: string;
}

export interface McpTokenResponse {
	access_token: string;
	token_type: "Bearer" | "DPoP";
	expires_in: number;
	refresh_token?: string;
	scope: string;
	/** RFC 8693 section 2.2.1, set on token exchange responses. */
	issued_token_type?: string;
}

export interface McpTokenPayload {
	sub: string;
	iss: string;
	aud: string | string[];
	exp: number;
	iat: number;
	jti: string;
	scope: string;
	client_id: string;
	/** RFC 9449 confirmation claim: `jkt` is the bound key thumbprint. */
	cnf?: { jkt?: string };
	agent_id?: string;
	agent_type?: string;
	trust_tier?: string;
	act?: McpActorClaim;
	/** Signed delegation binding. Absent on unbound tokens. */
	theauth_dlg?: McpDelegationBinding;
}

/** RFC 8693 `act` claim. Each level names an actor and may nest the previous one. */
export interface McpActorClaim {
	sub?: string;
	client_id?: string;
	act?: McpActorClaim;
}

/** One hop of a delegation chain, outermost (current) actor first. */
export interface McpDelegationHop {
	sub: string;
	clientId?: string;
}

export interface McpSession {
	userId: string;
	clientId: string;
	scopes: string[];
	resource: string | null;
	expiresAt: Date;
	tokenId: string;
	dpopJkt?: string;
	agent?: { id: string; type?: string; trustTier?: string };
	delegationChain?: McpDelegationHop[];
	/** The verified `theauth_dlg` claim, when the token is bound. */
	binding?: McpDelegationBinding;
	/** Which freshness mode checked revocation, and when. */
	freshness?: McpSessionFreshness;
	/** Re-run revocation and binding checks live, for long running handlers and SSE streams. */
	revalidate?: McpRevalidate;
}

export interface McpAuthContext {
	config: Required<
		Pick<
			McpConfig,
			| "issuer"
			| "baseUrl"
			| "accessTokenTtl"
			| "refreshTokenTtl"
			| "refreshTokenAbsoluteTtl"
			| "codeTtl"
		>
	> &
		McpConfig;
	storeClient: (client: McpClient) => Promise<void>;
	findClient: (clientId: string) => Promise<McpClient | null>;
	storeAuthorizationCode: (code: McpAuthorizationCode) => Promise<void>;
	consumeAuthorizationCode: (code: string) => Promise<McpAuthorizationCode | null>;
	storeToken: (token: McpAccessToken) => Promise<void>;
	findTokenByRefreshToken: (refreshToken: string) => Promise<McpAccessToken | null>;
	/** Revoke a token (by stored access token value, which is its SHA-256 digest) */
	revokeToken: (accessToken: string) => Promise<void>;
	/** Optional: persist a hashed client secret in place of a legacy plaintext one after a successful check. Without it, legacy rows keep working but are not upgraded. */
	updateClientSecret?: (clientId: string, hashedSecret: string) => Promise<void>;
	/** Optional: delete the family's token rows. Return the live access tokens it held (jti and expiry) so they can be denylisted; a store that returns nothing leaves them valid until `exp`. */
	revokeTokenFamily?: (familyId: string) => Promise<void | McpFamilyAccessTokenRef[]>;
	/** Optional: bind a client to an agent (or clear the binding with `null`). Required for `clients.bindAgent` and `clients.unbindAgent`; the database stores provide it. */
	setClientAgent?: (clientId: string, agentId: string | null) => Promise<void>;
	/** Admin disable or enable of a stored client. */
	setClientDisabled?: (
		clientId: string,
		disabled: boolean,
		reason?: string | null,
	) => Promise<void>;
	/** Deletes the client's token rows (refresh tokens die with them) and returns the jtis so a denylist can refuse live access tokens. */
	revokeClientTokens?: (
		clientId: string,
	) => Promise<{ jtis: Array<{ jti: string; expiresAt: Date }> }>;
	/** Admin blocks for Client ID Metadata Document clients. The resolver checks it before any fetch. */
	clientBlocks?: McpClientBlockStore;
	/** Optional: how many stored Client ID Metadata Document clients have never been consented to (no tokens, no agent binding, not disabled). Enables the cap `clientIdMetadataDocuments.maxUnconsentedClients`. */
	countUnconsentedCimdClients?: () => Promise<number>;
	/** Optional: deletes unconsented CIMD clients not updated since `before`. Returns how many were removed. */
	deleteStaleUnconsentedCimdClients?: (before: Date) => Promise<number>;
	/** Optional: every stored CIMD client_id, so a host block can revoke the tokens of that host's clients. */
	listCimdClientIds?: () => Promise<string[]>;
	/** Operator diagnostics, for example the notice that CIMD fetches run without a DNS resolver. */
	logger?: TheAuthLogger;
	tokenFamilies?: McpTokenFamilyStore;
	resolveUserId: (request: Request) => Promise<string | null>;
}

export interface ApproveConsentParams {
	userId: string;
	clientId: string;
	scope: string | string[];
	state?: string;
	redirectUri: string;
	codeChallenge: string;
	codeChallengeMethod: "S256";
	resource: string;
}

export interface McpAuthModule {
	getMetadata: () => McpServerMetadata;
	getProtectedResourceMetadata: () => McpProtectedResourceMetadata;
	registerClient: (
		body: McpClientRegistrationRequest,
		request?: Request,
	) => Promise<Result<McpClientRegistrationResponse>>;
	/** Bind OAuth clients to agents. A bound client's tokens carry `agent_id` and the delegation check resolves the client to that agent. */
	clients: McpClientBindings;
	/** Admin API for Client ID Metadata Document clients: blocks, refresh, enable, inspect. Admin only, never expose it to clients. */
	cimd: McpCimdAdmin;
	/** Facts the consent page must show for a client (verified host first, warnings). Resolves a CIMD client_id, so it may fetch its document. Without `redirectUri` the client's first registered one is described. */
	describeClient: (
		clientId: string,
		redirectUri?: string,
		options?: { firstUse?: boolean },
	) => Promise<Result<ClientDescription>>;
	authorize: (request: Request) => Promise<Result<McpAuthorizeResult>>;
	/** Issues an authorization code after the user approves consent. */
	approveConsent: (params: ApproveConsentParams) => Promise<Result<{ redirectUri: string }>>;
	token: (request: Request) => Promise<Result<McpTokenResponse>>;
	getJwks: () => Promise<{ keys: JWK[] }>;
	revoke: (request: Request) => Promise<Result<Record<string, never>>>;
	/** RFC 7662 introspection (client auth required, always live). */
	introspect: (request: Request) => Promise<Result<McpIntrospectionResponse>>;
	validateToken: (token: string, requiredScopes?: string[]) => Promise<Result<McpSession>>;
	middleware: (request: Request) => Promise<Result<McpSession>>;
	buildStepUpResponse: (options: {
		currentScopes: string[];
		requiredScopes: string[];
		resource?: string;
	}) => Response;
	/** Wraps a Web API handler so it runs only for a valid Bearer or DPoP token. */
	requireMcpAuth: (
		handler: McpProtectedHandler,
		options?: RequireMcpAuthOptions,
	) => (request: Request) => Promise<Response>;
	requireScopes: (request: Request, requiredScopes: string[]) => Promise<RequireScopesResult>;
}

// Zod Schemas
// Defined in schemas.ts, re-exported here so existing imports keep working.

export {
	McpAuthorizeRequestSchema,
	McpClientRegistrationSchema,
	type McpTokenRequestParsed,
	McpTokenRequestSchema,
} from "./schemas.js";
