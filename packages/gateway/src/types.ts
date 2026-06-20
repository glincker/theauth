import type { Kavach } from "theauth";

// ─── Gateway Configuration ───────────────────────────────────────────────────

export interface CorsConfig {
	/** Allowed origins. Use '*' to allow all. Default: '*' */
	origins?: string | string[];
	/** Allowed methods. Default: all common HTTP methods */
	methods?: string[];
	/** Allowed headers. Default: 'Content-Type, Authorization' */
	headers?: string[];
	/** Max age for preflight cache in seconds. Default: 86400 */
	maxAge?: number;
	/** Whether to allow credentials. Default: false */
	credentials?: boolean;
}

export interface RateLimitConfig {
	/** Window duration in milliseconds */
	windowMs: number;
	/** Maximum requests allowed within the window */
	max: number;
}

export interface GatewayPolicy {
	/** Glob pattern to match request paths. e.g. '/api/*', '/tools/**' */
	path: string;
	/** HTTP method(s) to match. Matches all methods if omitted. */
	method?: string | string[];
	/** Whether to require a valid auth token. Default: true */
	requireAuth?: boolean;
	/** Permissions required for access */
	requiredPermissions?: Array<{
		resource: string;
		actions: string[];
	}>;
	/** Per-policy rate limit override */
	rateLimit?: RateLimitConfig;
	/** Mark this path as public (no auth required, overrides requireAuth) */
	public?: boolean;
}

export interface GatewayConfig {
	/** URL of the upstream service to proxy to */
	upstream: string;
	/** Base path prefix for all proxied routes. Default: '/' */
	basePath?: string;
	/** TheAuth instance */
	kavach: Kavach;
	/** Path-based access policies */
	policies?: GatewayPolicy[];
	/** CORS configuration */
	cors?: CorsConfig;
	/** Global rate limit (per agent or IP) */
	rateLimit?: RateLimitConfig;
	/** Record an audit entry for every request. Default: true */
	audit?: boolean;
	/** Remove the Authorization header before forwarding. Default: false */
	stripAuthHeader?: boolean;
}

// ─── Gateway Public Interface ────────────────────────────────────────────────

export interface Gateway {
	/** Handle a Web API Request and return a Response */
	handleRequest(request: Request): Promise<Response>;
	/** Start a standalone HTTP server on the given port */
	listen(port: number): Promise<void>;
	/** Shut down the standalone HTTP server */
	close(): Promise<void>;
}

// ─── Internal Types ──────────────────────────────────────────────────────────

export interface ResolvedIdentity {
	agentId: string;
	ownerId: string;
	token: string;
}

export interface RateLimitEntry {
	timestamps: number[];
}
