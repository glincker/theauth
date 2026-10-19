/** HTTP surface for TheAuth core: one web-standard handler that the framework adapters wrap. */

export type { Cors, CorsDecision, CorsGroup, CorsOptions } from "./cors.js";
export { corsGroupOf, createCors } from "./cors.js";
export type { ToWebRequestOptions } from "./node.js";
export {
	peerAddressOf,
	RequestBodyTooLargeError,
	resolveRequestIp,
	sendWebResponse,
	toWebRequest,
} from "./node.js";
export type { RequireAgentOptions, RequireAgentResult } from "./require-agent.js";
export {
	agentCredentialOf,
	bearerTokenOf,
	requireAgent,
	statusForDecisionCode,
} from "./require-agent.js";
export { createTheAuthHandler, listRoutes, resolveMountedMcpRoutes } from "./router.js";
export type { SecurityHeadersInput, SecurityHeadersOptions } from "./security-headers.js";
export { isSecureRequest, securityHeaders } from "./security-headers.js";
export type {
	RouteAuthLevel,
	RouteSpec,
	TheAuthHandler,
	TheAuthHandlerOptions,
} from "./types.js";
