/** HTTP surface for TheAuth core: one web-standard handler that the framework adapters wrap. */

export type { ToWebRequestOptions } from "./node.js";
export {
	peerAddressOf,
	RequestBodyTooLargeError,
	resolveRequestIp,
	sendWebResponse,
	toWebRequest,
} from "./node.js";
export type { RequireAgentOptions, RequireAgentResult } from "./require-agent.js";
export { bearerTokenOf, requireAgent, statusForDecisionCode } from "./require-agent.js";
export { createTheAuthHandler, listRoutes, resolveMountedMcpRoutes } from "./router.js";
export type {
	RouteAuthLevel,
	RouteSpec,
	TheAuthHandler,
	TheAuthHandlerOptions,
} from "./types.js";
