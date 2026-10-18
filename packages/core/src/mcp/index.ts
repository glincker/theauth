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
export { CLIENT_ASSERTION_ALGS, verifyClientAssertion } from "./client-assertion.js";
// Client ID Metadata Documents and SSRF-safe fetching
export {
	cimdCacheSeconds,
	fetchClientMetadataDocument,
	resolveClient,
} from "./client-metadata.js";
export { approveConsent } from "./consent.js";
export { createDbDelegationStore } from "./delegation-check.js";
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
	generateMcpSigningKey,
	getJwks,
	type McpSigningKeyPair,
	toPublicJwk,
} from "./keys.js";
export { createInMemoryJtiDenylist, createInMemoryTokenFamilyStore } from "./memory-stores.js";
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
export {
	type DnsResolver,
	isBlockedIp,
	type SafeFetchOptions,
	type SafeFetchResult,
	safeFetchJson,
} from "./safe-fetch.js";
export { createMcpModule, createMcpResponseHelpers } from "./server.js";
export { buildStepUpResponse } from "./step-up.js";
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
	McpAuthModule,
	McpAuthorizationCode,
	McpAuthorizeRequest,
	McpAuthorizeResult,
	McpClient,
	McpClientRegistrationRequest,
	McpClientRegistrationResponse,
	McpConfig,
	McpDelegationHop,
	McpDelegationLink,
	McpDelegationStore,
	McpJtiDenylist,
	McpProtectedResourceMetadata,
	McpServerMetadata,
	McpSession,
	McpSigningConfig,
	McpTokenFamilyStore,
	McpTokenPayload,
	McpTokenRequest,
	McpTokenRequestParsed,
	McpTokenResponse,
	Result,
	TheAuthError,
} from "./types.js";
export {
	McpAuthorizeRequestSchema,
	McpClientRegistrationSchema,
	McpTokenRequestSchema,
} from "./types.js";
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
