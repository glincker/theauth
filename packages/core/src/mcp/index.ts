// ─── MCP OAuth 2.1 Authorization Server Module ─────────────────────────────
//
// Implements:
// - OAuth 2.1 (draft-ietf-oauth-v2-1-13)
// - PKCE with S256 (mandatory, no plain)
// - Authorization Server Metadata (RFC 8414)
// - Protected Resource Metadata (RFC 9728)
// - Dynamic Client Registration (RFC 7591)
// - Resource Indicators (RFC 8707)
// - Token audience binding

// Authorization endpoint
export { handleAuthorize } from "./authorize.js";
// Consent approval
export { approveConsent } from "./consent.js";
// Metadata endpoints
export {
	getAuthorizationServerMetadata,
	getProtectedResourceMetadata,
} from "./metadata.js";
// Dynamic Client Registration
export { registerClient } from "./registration.js";
// Scope challenge helper
export { requireScopes } from "./require-scopes.js";
// Module factory
export { createMcpModule, createMcpResponseHelpers } from "./server.js";
// Step-up authorization
export { buildStepUpResponse } from "./step-up.js";
// Token endpoint
export { handleTokenExchange } from "./token.js";
// Types
export type {
	ApproveConsentParams,
	KavachError,
	McpAccessToken,
	McpAuthContext,
	McpAuthModule,
	McpAuthorizationCode,
	McpAuthorizeRequest,
	McpAuthorizeResult,
	McpClient,
	McpClientRegistrationRequest,
	McpClientRegistrationResponse,
	McpConfig,
	McpProtectedResourceMetadata,
	McpServerMetadata,
	McpSession,
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
	parseRequestBody,
	verifyS256,
} from "./utils.js";
// Token validation & middleware
export {
	buildUnauthorizedResponse,
	validateAccessToken,
	withMcpAuth,
} from "./validate.js";
