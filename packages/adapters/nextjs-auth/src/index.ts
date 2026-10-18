import "server-only";

export { fetchWithRefresh, GraphQLRequestError, graphqlWithRefresh } from "./backend-fetch.js";
export { createAuthConfig } from "./config.js";
export {
	clearAllAuthCookies,
	clearAllAuthCookiesFromStore,
	getCsrfToken,
	getSessionToken,
	hasSessionCookie,
	setSessionCookies,
} from "./cookies.js";
export { createCsrfToken, generateCsrfToken, verifyCsrfToken } from "./csrf.js";
export { verifyCsrfRequest } from "./csrf-verify.js";
export { buildAuthHeaders, buildClientHeaders } from "./headers.js";
export { refreshSession } from "./refresh.js";
export {
	createSignOutAction,
	createSignOutHandler,
	createSignOutRouteHandler,
} from "./route-handlers.js";
export { safeRedirectPath } from "./safe-redirect.js";
export { getServerSession } from "./server-session.js";

export type {
	AuthConfig,
	AuthCookieConfig,
	AuthEndpoints,
	AuthSession,
	DefaultUser,
	RefreshResult,
	ResolvedAuthConfig,
	SessionCacheEntry,
} from "./types.js";
