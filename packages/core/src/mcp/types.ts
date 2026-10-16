import type { JWK } from "jose";
import type { SecondaryStorage } from "../storage/types.js";
import type { McpDpopConfig } from "./dpop-types.js";
import type {
	McpClientCredentialsConfig,
	McpJwtBearerConfig,
	McpLenientClientsConfig,
	McpTokenExchangeConfig,
} from "./grant-types.js";
import type { McpProtectedHandler, RequireMcpAuthOptions } from "./require-mcp-auth.js";
import type { DnsResolver } from "./safe-fetch.js";

// Result Type

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

// MCP Module Configuration

export interface McpConfig {
	/** Enable MCP authorization server */
	enabled: boolean;
	/** Enforce auth on all MCP requests */
	enforceAuth?: boolean;
	/** Custom scopes supported by this server */
	scopes?: string[];
	/** Issuer URL (typically your base URL) */
	issuer?: string;
	/** Base URL for MCP endpoints */
	baseUrl?: string;
	/**
	 * Secret key for HS256 signing (must be >= 32 chars). Required unless
	 * `signing` is set. When both are set, new tokens use `signing` and HS256
	 * tokens issued earlier are still accepted until they expire.
	 */
	signingSecret?: string;
	/**
	 * Opt in to asymmetric signing (ES256 or EdDSA). Tokens get a `kid`
	 * header, public keys are served by `getJwks()`, and `previous` keys stay
	 * published and accepted so rotation does not invalidate live tokens.
	 */
	signing?: McpSigningConfig;
	/**
	 * Canonical URI of this resource server (RFC 8707). `middleware`,
	 * `validateToken` and `requireScopes` check the token audience against it
	 * and refuse to run without it.
	 */
	resource?: string;
	/**
	 * Optional jti denylist. When set, revoked access tokens (refresh rotation,
	 * reuse detection, the revocation endpoint) are rejected by
	 * `validateAccessToken` even though they are still validly signed.
	 */
	jtiDenylist?: McpJtiDenylist;
	/**
	 * Opt in to a live delegation check. When set, `validateAccessToken` walks the
	 * token's `act` chain (subject, then each actor) against live link records and
	 * rejects the token if any link is missing, revoked or expired. Off by default,
	 * so a token minted down a chain stays valid until `exp` unless this is set.
	 */
	delegationStore?: McpDelegationStore;
	/**
	 * Opt in to DPoP (RFC 9449). When set, the token endpoint accepts a `DPoP`
	 * proof and issues `cnf.jkt`-bound tokens, `requireMcpAuth` accepts the
	 * `DPoP` scheme, and metadata advertises the supported algorithms. Off by
	 * default; bearer tokens keep working unless `required` is true.
	 */
	dpop?: McpDpopConfig;
	/**
	 * Refresh token family store used for rotation and reuse detection. Defaults
	 * to an in-process store (single instance only). Pass
	 * `createTokenFamilyStore(db)` for a durable, multi-instance store.
	 */
	tokenFamilies?: McpTokenFamilyStore;
	/**
	 * Client ID Metadata Documents (client_id is an https URL). Off by default.
	 * When enabled, unknown https client_ids are fetched through an SSRF-safe
	 * fetcher and must contain a matching `client_id`.
	 */
	clientIdMetadataDocuments?: {
		enabled: boolean;
		/** DNS resolver override (tests, edge runtimes). */
		resolver?: DnsResolver;
		/** Fetch override, for example one that pins the connection to the resolved IP. */
		fetchImpl?: typeof fetch;
		/** Restrict to these hostnames when set. */
		allowedHosts?: string[];
		/**
		 * Seconds a failed document fetch is remembered before the next attempt.
		 * Default 30; 0 disables the negative cache.
		 */
		negativeCacheSeconds?: number;
	};
	/**
	 * Compatibility switches for lenient MCP clients (optional resource, dropped
	 * unknown scopes, loopback redirect ports, path-prefix audiences). Off by
	 * default; see {@link McpLenientClientsConfig}.
	 */
	lenientClients?: McpLenientClientsConfig;
	/**
	 * Opt in to the `client_credentials` grant for confidential clients. Needs a
	 * `resolvePrincipal` mapping. Tokens are scope-limited, carry no refresh
	 * token and can be DPoP-bound.
	 */
	clientCredentials?: McpClientCredentialsConfig;
	/**
	 * Opt in to RFC 8693 token exchange. Requires `jtiDenylist` so revoked
	 * subject tokens are refused.
	 */
	tokenExchange?: McpTokenExchangeConfig;
	/**
	 * Opt in to RFC 7523 `jwt-bearer` redemption of ID-JAG assertions
	 * (`typ: oauth-id-jag+jwt`) from trusted issuers.
	 */
	jwtBearer?: McpJwtBearerConfig;
	/**
	 * Replay cache for `private_key_jwt` client assertions and jwt-bearer
	 * assertions (`jti`). Defaults to an in-process store (single instance
	 * only); pass shared storage in multi-instance deployments.
	 */
	assertionStorage?: SecondaryStorage;
	/** Access token TTL in seconds (default: 3600) */
	accessTokenTtl?: number;
	/** Refresh token TTL in seconds (default: 604800 = 7 days) */
	refreshTokenTtl?: number;
	/**
	 * Absolute lifetime of a refresh token family in seconds (default: 2592000,
	 * 30 days). Rotation slides the per-token expiry but never extends past this.
	 */
	refreshTokenAbsoluteTtl?: number;
	/** Authorization code TTL in seconds (default: 600 = 10 minutes) */
	codeTtl?: number;
	/** Allowed resource URIs for RFC 8707 */
	allowedResources?: string[];
	/** Login page URL - where users are redirected to authenticate */
	loginPage?: string;
	/** Consent page URL - where users approve scopes */
	consentPage?: string;
	/**
	 * Clients that are pre-registered at startup.
	 *
	 * These are stored via `storeClient` when the module is created,
	 * so they behave identically to dynamically-registered clients.
	 * Useful for first-party apps, CLIs, or test fixtures that should
	 * always exist without a prior registration call.
	 */
	preRegisteredClients?: Array<{
		clientId: string;
		clientSecret?: string;
		redirectUris: string[];
		clientName?: string;
		scope?: string;
		/**
		 * Grant types this client may use. Default: authorization_code and
		 * refresh_token. List `client_credentials`, the token-exchange URN or
		 * the jwt-bearer URN here to allow those grants for the client.
		 */
		grantTypes?: string[];
	}>;
	/** Custom token claims generator */
	getAdditionalClaims?: (userId: string, scopes: string[]) => Promise<Record<string, unknown>>;
	/**
	 * Emit IETF agentic JWT claims on issued access tokens.
	 *
	 * When true, any claims returned by `getAgenticContext` are embedded in
	 * the token payload using the registered draft-goswami-agentic-jwt-00 claim
	 * names. Claims with no available context value are omitted. Off by default.
	 *
	 * @default false
	 */
	emitAgenticJwtClaims?: boolean;
	/**
	 * Resolve agentic context for a given user at token issuance time.
	 *
	 * Called only when `emitAgenticJwtClaims` is true. Return only the claims
	 * you can populate; absent fields are skipped rather than fabricated.
	 *
	 * TODO(v3): wire this through theauth.ts so the trust module can provide
	 * trust_tier automatically without requiring the caller to implement it.
	 */
	getAgenticContext?: (userId: string) => Promise<{
		agentId?: string;
		agentType?: "autonomous" | "delegated" | "supervised";
		trustTier?: "unverified" | "low" | "standard" | "elevated" | "high";
	}>;
}

export type McpAsymmetricAlg = "ES256" | "EdDSA";

export interface McpSigningConfig {
	alg: McpAsymmetricAlg;
	/** Key used to sign new tokens. */
	current: { kid: string; privateKey: JWK };
	/** Retired keys that remain published and accepted for verification. */
	previous?: Array<{ kid: string; publicKey: JWK }>;
}

export interface McpJtiDenylist {
	/** Deny a token id until `expiresAt`, after which the entry may be dropped. */
	revoke: (jti: string, expiresAt: Date) => Promise<void>;
	isRevoked: (jti: string) => Promise<boolean>;
}

/** A live delegation link between two actors. */
export interface McpDelegationLink {
	status: "active" | "revoked" | "expired";
	expiresAt: Date;
}

/** Lookup of live delegation links, keyed by the `sub` values used in `act` claims. */
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
	registration_endpoint: string;
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
	userId: string | null;
	/** Set to "cimd" for clients resolved from a Client ID Metadata Document. */
	source?: "cimd";
	/** Public keys for `private_key_jwt` client authentication. */
	jwks?: { keys: JWK[] };
	/** HTTPS URL of the client's JWKS, for `private_key_jwt`. */
	jwksUri?: string;
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

// Authorization Code

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

// Authorization Request

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

// Access Token

export interface McpAccessToken {
	/**
	 * SHA-256 hex digest of the access token JWT. The raw token is never
	 * handed to storage. Rows written by older versions hold the raw JWT.
	 */
	accessToken: string;
	/**
	 * SHA-256 hex digest of the refresh token, or null. Rows written by older
	 * versions hold the raw value; lookups fall back to it once.
	 */
	refreshToken: string | null;
	/** Token id (`jti` claim). */
	jti?: string;
	/** Refresh token family, used for reuse detection (RFC 9700). */
	familyId?: string;
	tokenType: "Bearer" | "DPoP";
	/**
	 * RFC 7638 thumbprint of the DPoP key this grant is bound to. Persist it:
	 * the refresh grant refuses any other key. Absent for bearer grants.
	 */
	dpopJkt?: string;
	expiresIn: number;
	scope: string[];
	clientId: string;
	userId: string;
	resource: string | null;
	expiresAt: Date;
	createdAt: Date;
}

// Token Request / Response

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

// Token Validation

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
	/** RFC 8693 actor claim, nested for a delegation chain. */
	act?: McpActorClaim;
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
	/** Thumbprint of the DPoP key the token is bound to, when it is bound. */
	dpopJkt?: string;
	/** Agent identity claims, when the token carries them. */
	agent?: { id: string; type?: string; trustTier?: string };
	/** Delegation chain from `act` claims, current actor first. Empty when none. */
	delegationChain?: McpDelegationHop[];
}

// MCP Auth Context (passed to all handler functions)

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
	/** Store a client registration */
	storeClient: (client: McpClient) => Promise<void>;
	/** Find a client by ID */
	findClient: (clientId: string) => Promise<McpClient | null>;
	/** Store an authorization code */
	storeAuthorizationCode: (code: McpAuthorizationCode) => Promise<void>;
	/** Find and consume an authorization code (must delete after finding) */
	consumeAuthorizationCode: (code: string) => Promise<McpAuthorizationCode | null>;
	/** Store an access token record */
	storeToken: (token: McpAccessToken) => Promise<void>;
	/** Find a token by refresh token value */
	findTokenByRefreshToken: (refreshToken: string) => Promise<McpAccessToken | null>;
	/** Revoke a token (by stored access token value, which is its SHA-256 digest) */
	revokeToken: (accessToken: string) => Promise<void>;
	/**
	 * Optional: persist a hashed client secret in place of a legacy plaintext
	 * one after a successful check. Without it, legacy rows keep working but
	 * are not upgraded.
	 */
	updateClientSecret?: (clientId: string, hashedSecret: string) => Promise<void>;
	/** Optional: revoke every stored token that belongs to a refresh token family. */
	revokeTokenFamily?: (familyId: string) => Promise<void>;
	/** Resolved family store (always set by `createMcpModule`). */
	tokenFamilies?: McpTokenFamilyStore;
	/** Resolve the authenticated user ID (e.g., from session cookie) */
	resolveUserId: (request: Request) => Promise<string | null>;
}

// MCP Module (public API shape)

export interface ApproveConsentParams {
	/** Authenticated user who approved the consent */
	userId: string;
	clientId: string;
	/** Space-separated scope string or array */
	scope: string | string[];
	state?: string;
	redirectUri: string;
	codeChallenge: string;
	codeChallengeMethod: "S256";
	resource: string;
}

export interface McpAuthModule {
	/** Get OAuth 2.0 Authorization Server Metadata */
	getMetadata: () => McpServerMetadata;
	/** Get Protected Resource Metadata (RFC 9728) */
	getProtectedResourceMetadata: () => McpProtectedResourceMetadata;
	/** Register a new OAuth client (RFC 7591) */
	registerClient: (
		body: McpClientRegistrationRequest,
	) => Promise<Result<McpClientRegistrationResponse>>;
	/** Handle authorization request */
	authorize: (request: Request) => Promise<Result<McpAuthorizeResult>>;
	/**
	 * Issue an authorization code after a user has explicitly approved consent.
	 *
	 * When `config.consentPage` is set, `authorize` redirects to that page
	 * instead of issuing a code directly.  The consent page must call this
	 * method after the user clicks "Allow".
	 */
	approveConsent: (params: ApproveConsentParams) => Promise<Result<{ redirectUri: string }>>;
	/** Handle token exchange */
	token: (request: Request) => Promise<Result<McpTokenResponse>>;
	/** Public JWKS (RFC 7517). Empty when HS256 is used. */
	getJwks: () => Promise<{ keys: JWK[] }>;
	/** RFC 7009 token revocation. Always succeeds for unknown tokens. */
	revoke: (request: Request) => Promise<Result<Record<string, never>>>;
	/** Validate an access token */
	validateToken: (token: string, requiredScopes?: string[]) => Promise<Result<McpSession>>;
	/** Middleware that validates Bearer tokens and returns session */
	middleware: (request: Request) => Promise<Result<McpSession>>;
	/** Build a step-up challenge response (403) indicating required scopes */
	buildStepUpResponse: (options: {
		currentScopes: string[];
		requiredScopes: string[];
		resource?: string;
	}) => Response;
	/**
	 * Wrap a Web API handler so it only runs for a valid Bearer or DPoP token.
	 * The handler receives the verified principal. See `requireMcpAuth`.
	 */
	requireMcpAuth: (
		handler: McpProtectedHandler,
		options?: RequireMcpAuthOptions,
	) => (request: Request) => Promise<Response>;
	/** Validate token and check scopes. Returns session if valid, or a Response to send back */
	requireScopes: (
		request: Request,
		requiredScopes: string[],
	) => Promise<
		{ authorized: true; session: McpSession } | { authorized: false; response: Response }
	>;
}

// Zod Schemas
// Defined in schemas.ts, re-exported here so existing imports keep working.

export {
	McpAuthorizeRequestSchema,
	McpClientRegistrationSchema,
	type McpTokenRequestParsed,
	McpTokenRequestSchema,
} from "./schemas.js";
