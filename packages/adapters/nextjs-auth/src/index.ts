import "server-only";

// Backend fetch utilities
export { fetchWithRefresh, GraphQLRequestError, graphqlWithRefresh } from "./backend-fetch.js";
// Config factory
export { createAuthConfig } from "./config.js";
// Cookie helpers (for advanced consumers)
export {
	clearAllAuthCookies,
	clearAllAuthCookiesFromStore,
	getCsrfToken,
	getSessionToken,
	hasSessionCookie,
	setSessionCookies,
} from "./cookies.js";
// CSRF
export { generateCsrfToken } from "./csrf.js";
// Header builders
export { buildAuthHeaders, buildClientHeaders } from "./headers.js";
// Refresh
export { refreshSession } from "./refresh.js";
// Sign-out handler factory (createSignOutAction is a deprecated alias)
export { createSignOutAction, createSignOutHandler } from "./route-handlers.js";
// Session
export { getServerSession } from "./server-session.js";

// Types
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
