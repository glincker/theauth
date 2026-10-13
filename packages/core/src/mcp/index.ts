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

// Authorization endpoint
export { handleAuthorize } from "./authorize.js";
// private_key_jwt client authentication
export { CLIENT_ASSERTION_ALGS, verifyClientAssertion } from "./client-assertion.js";
// Client ID Metadata Documents and SSRF-safe fetching
export {
	cimdCacheSeconds,
	fetchClientMetadataDocument,
	resolveClient,
} from "./client-metadata.js";
// Consent approval
export { approveConsent } from "./consent.js";
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
// Signing keys and JWKS
export {
	generateMcpSigningKey,
	getJwks,
	type McpSigningKeyPair,
	toPublicJwk,
} from "./keys.js";
export { createInMemoryJtiDenylist, createInMemoryTokenFamilyStore } from "./memory-stores.js";
// Metadata endpoints
export {
	getAuthorizationServerMetadata,
	getProtectedResourceMetadata,
} from "./metadata.js";
// Dynamic Client Registration
export { registerClient } from "./registration.js";
// Resource server wrapper
export {
	type McpPrincipal,
	type McpProtectedHandler,
	type RequireMcpAuthOptions,
	requireMcpAuth,
} from "./require-mcp-auth.js";
// Scope challenge helper
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
// Module factory
export { createMcpModule, createMcpResponseHelpers } from "./server.js";
// Step-up authorization
export { buildStepUpResponse } from "./step-up.js";
// Token endpoint
export { handleTokenExchange } from "./token.js";
// Types
export type {
	ApproveConsentParams,
	AuthError,
	McpAccessToken,
	McpActorClaim,
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
// Zod schemas
export {
	McpAuthorizeRequestSchema,
	McpClientRegistrationSchema,
	McpTokenRequestSchema,
} from "./types.js";
// Utilities (for adapter authors)
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
// Token validation & middleware
export {
	buildUnauthorizedResponse,
	validateAccessToken,
	withMcpAuth,
} from "./validate.js";
