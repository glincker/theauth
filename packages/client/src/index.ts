export type {
	AuthClient,
	AuthClientOptions,
	AuthorizeRequest,
	TheAuthClient,
	TheAuthClientOptions,
} from "./client.js";
export { createAuthClient, createTheAuthClient } from "./client.js";
export type {
	DPoPClient,
	DPoPClientOptions,
	DPoPFetchOptions,
	DPoPProofInput,
	DPoPProver,
	DPoPProverOptions,
	DPoPPublicJwk,
} from "./dpop.js";
export { createDPoPClient, createDPoPProver, normalizeHtu } from "./dpop.js";
export type {
	EndpointCallInput,
	EndpointClient,
	EndpointClientOptions,
	EndpointResult,
	RouteShape,
} from "./endpoint-client.js";
export { createEndpointClient } from "./endpoint-client.js";
export { AuthApiError, TheAuthApiError } from "./error.js";
export {
	createTheAuthGoClient,
	GO_ERROR_HTTP,
	GO_ERROR_NETWORK,
	GO_ERROR_PASSKEY_CANCELLED,
	GO_ERROR_PASSKEY_UNSUPPORTED,
} from "./go-client.js";
export type { GoThrottleError } from "./go-errors.js";
export {
	GO_CODE_ACCOUNT_LOCKED,
	GO_CODE_BEARER_REQUIRED,
	GO_CODE_RATE_LIMITED,
	GO_CODE_RECENT_AUTH_REQUIRED,
	isBearerRequired,
	isRecentAuthRequired,
	isThrottleError,
} from "./go-errors.js";
export type {
	ApiTokenKind,
	BootstrapStatus,
	DeviceCode,
	DeviceCodeInput,
	DevicePollOptions,
	DeviceRequestInfo,
	DeviceToken,
	GoAgent,
	GoAgentCredential,
	GoApiToken,
	GoAuthError,
	GoAuthResult,
	GoCurrentToken,
	GoDelegation,
	GoSession,
	GoUser,
	GrantDelegationInput,
	ListApiTokensOptions,
	LoginResult,
	MintApiTokenInput,
	MintedApiToken,
	PasskeyCredential,
	RegisterAgentInput,
	RegisteredAgent,
	SignupInput,
	StepUpMethod,
	StepUpProof,
	StepUpResult,
	TheAuthGoClient,
	TheAuthGoClientOptions,
	TotpEnrollment,
	TotpStatus,
} from "./go-types.js";
export type {
	PasskeyClient,
	PasskeyClientOptions,
	PasskeyResult,
	PasskeySession,
	PasskeySignInOptions,
} from "./passkey.js";
export { createPasskeyClient } from "./passkey.js";
export type { EventTargetLike, RefetchEnvironment, RefetchOptions } from "./refetch.js";
export { attachRefetch } from "./refetch.js";
export type {
	HydrateInput,
	SessionState,
	SessionStorageLike,
	SessionStore,
	SessionStoreOptions,
	StoreActionResult,
	StoreSession,
	StoreUser,
} from "./session-store.js";
export { createSessionStore, EMAIL_PASSWORD_ROUTES } from "./session-store.js";
export type { SolidAuth, SolidPrimitives } from "./solid.js";
export { createSolidAuth } from "./solid.js";
export type {
	Agent,
	AgentFilters,
	AuditEntry,
	AuditFilters,
	AuthApiErrorBody,
	AuthError,
	AuthorizeByTokenInput,
	AuthorizeResult,
	AuthResult,
	CreateAgentInput,
	DelegateInput,
	DelegationChain,
	ExportOptions,
	McpServer,
	PaginatedAuditLogs,
	Permission,
	PermissionConstraints,
	RegisterMcpServerInput,
	TheAuthApiErrorBody,
	TheAuthError,
	TheAuthResult,
	UpdateAgentInput,
} from "./types.js";
export {
	assertionToJSON,
	attestationToJSON,
	base64UrlToBuffer,
	bufferToBase64Url,
	creationOptionsFromJSON,
	isPasskeySupported,
	requestOptionsFromJSON,
} from "./webauthn.js";
