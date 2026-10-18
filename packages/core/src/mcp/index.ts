// MCP OAuth 2.1 Authorization Server Module
//
// Implements:
// - OAuth 2.1 (draft-ietf-oauth-v2-1-13)
// - PKCE with S256 (mandatory, no plain)
// - Authorization Server Metadata (RFC 8414)
// - Protected Resource Metadata (RFC 9728)
// - Dynamic Client Registration (RFC 7591)
// - Resource Indicators (RFC 8707)
// - Token audience binding
// - Refresh token rotation with reuse detection (RFC 9700)
// - Token revocation (RFC 7009), issuer identification (RFC 9207)
// - Optional ES256/EdDSA signing with JWKS and key rotation

export { handleAuthorize } from "./authorize.js";
export { createCimdAdmin } from "./cimd-admin.js";
export {
	type ClientIdUrlCheck,
	checkClientIdUrl,
	looksLikeCimdClientId,
	matchesHostPattern,
	screenHostname,
} from "./cimd-url.js";
export { CLIENT_ASSERTION_ALGS, verifyClientAssertion } from "./client-assertion.js";
// Client ID Metadata Documents and SSRF-safe fetching
export {
	cimdCacheSeconds,
	fetchClientMetadataDocument,
	refreshCimdClient,
	resolveClient,
} from "./client-metadata.js";
export { approveConsent } from "./consent.js";
export { describeClientForConsent } from "./consent-view.js";
export { createDbDelegationStore } from "./delegation-check.js";
export { createDohResolver, type DohResolverOptions } from "./doh-resolver.js";
// DPoP (RFC 9449)
export {
	computeAth,
	DEFAULT_DPOP_ALGS,
	getCurrentDpopNonce,
	normalizeHtu,
	type VerifiedDpopProof,
	type VerifyDpopProofInput,
	verifyDpopProof,
} from "./dpop.js";
export type { DpopAlg, McpDpopConfig } from "./dpop-types.js";
// Non-interactive grants and lenient client options
export {
	CLIENT_ASSERTION_TYPE_JWT_BEARER,
	DEFAULT_MAX_CHAIN_DEPTH,
	GRANT_TYPE_CLIENT_CREDENTIALS,
	GRANT_TYPE_JWT_BEARER,
	GRANT_TYPE_TOKEN_EXCHANGE,
	ID_JAG_TYP,
	type McpClientCredentialsConfig,
	type McpClientPrincipal,
	type McpJwtBearerConfig,
	type McpJwtBearerSubjectInput,
	type McpLenientClientsConfig,
	type McpTokenExchangeConfig,
	type McpTokenExchangeInput,
	type McpTrustedIssuer,
	TOKEN_TYPE_ACCESS_TOKEN,
} from "./grant-types.js";
export {
	handleIntrospection,
	type McpIntrospectionAuditEvent,
	type McpIntrospectionHooks,
} from "./introspect.js";
export {
	generateMcpSigningKey,
	getJwks,
	type McpSigningKeyPair,
	toPublicJwk,
} from "./keys.js";
export type { LoginRedirectDetails } from "./login-redirect.js";
export { loginRedirectUrl } from "./login-redirect.js";
export {
	createInMemoryBlockStore,
	createInMemoryJtiDenylist,
	createInMemoryRevocationStore,
	createInMemoryTokenFamilyStore,
} from "./memory-stores.js";
export {
	ALL_MCP_ROUTES,
	applyMountedToResourceMetadata,
	applyMountedToServerMetadata,
	getAuthorizationServerMetadata,
	getProtectedResourceMetadata,
	type McpMountedRoutes,
	type McpMountedServerMetadata,
} from "./metadata.js";
export { registerClient } from "./registration.js";
export {
	type McpPrincipal,
	type McpProtectedHandler,
	type RequireMcpAuthOptions,
	requireMcpAuth,
} from "./require-mcp-auth.js";
export { requireScopes } from "./require-scopes.js";
// Token revocation (RFC 7009)
export { handleRevocation } from "./revocation.js";
export type * from "./revocation-types.js";
// Runtime values must be named: `export type *` does not export them.
export {
	MCP_DEFAULT_FRESHNESS_MODE_WITH_DB,
	MCP_DEFAULT_FRESHNESS_MODE_WITHOUT_DB,
	MCP_DELEGATION_BINDING_VERSION,
	MCP_DELEGATION_CLAIM,
	MCP_FRESHNESS_MODES,
	MCP_REVOCATION_DEFAULTS,
} from "./revocation-types.js";
export {
	type DnsResolver,
	isBlockedIp,
	type SafeFetchOptions,
	type SafeFetchResult,
	safeFetchJson,
} from "./safe-fetch.js";
export {
	createMcpModule,
	createMcpResponseHelpers,
	type McpModuleAuth,
	type McpModuleParams,
} from "./server.js";
export type { McpUserAuthRequirement } from "./step-up.js";
export {
	buildInsufficientUserAuthResponse,
	buildStepUpResponse,
	checkUserAuthentication,
} from "./step-up.js";
export { createMcpStores, type McpStores, type McpStoresOptions } from "./stores-db.js";
export { createDbBindingStore } from "./stores-db-binding.js";
export { createDbRevocationStore } from "./stores-db-revocation.js";
export { handleTokenExchange } from "./token.js";
export type {
	ApproveConsentParams,
	AuthError,
	McpAccessToken,
	McpActorAgentResolver,
	McpActorClaim,
	McpActorRef,
	McpAsymmetricAlg,
	McpAuthContext,
	McpAuthErrorCode,
	McpAuthEvidence,
	McpAuthModule,
	McpAuthorizationCode,
	McpAuthorizeRequest,
	McpAuthorizeResult,
	McpClient,
	McpClientBindings,
	McpClientRegistrationRequest,
	McpClientRegistrationResponse,
	McpConfig,
	McpDelegationHop,
	McpDelegationLink,
	McpDelegationStore,
	McpJtiDenylist,
	McpProtectedResourceMetadata,
	McpRegistrationConfig,
	McpRejectedToken,
	McpServerMetadata,
	McpSession,
	McpSigningConfig,
	McpTokenFamilyStore,
	McpTokenPayload,
	McpTokenRequest,
	McpTokenRequestParsed,
	McpTokenResponse,
	RequireScopesResult,
	Result,
	TheAuthError,
} from "./types.js";
export {
	McpAuthorizeRequestSchema,
	McpClientRegistrationSchema,
	McpTokenRequestSchema,
} from "./types.js";
export type * from "./types-cimd.js";
// Runtime values must be named: `export type *` does not export them.
export {
	CIMD_DISABLED_REASON_BLOCKED,
	CIMD_DISABLED_REASON_CHANGED_WHILE_BOUND,
} from "./types-cimd.js";
export {
	computeS256Challenge,
	extractBasicAuth,
	extractBearerToken,
	generateSecureToken,
	hashClientSecret,
	hashToken,
	parseRequestBody,
	timingSafeEqual,
	verifyClientSecret,
	verifyS256,
} from "./utils.js";
export {
	buildUnauthorizedResponse,
	validateAccessToken,
	withMcpAuth,
} from "./validate.js";
