import type { TheAuth, TrustedProxyConfig } from "@glinr/theauth";
import type { McpAuthModule } from "@glinr/theauth/mcp";

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
	windowMs: number;
	max: number;
}

export interface GatewayPolicy {
	/** Glob pattern to match request paths. e.g. '/api/*', '/tools/**' */
	path: string;
	/** HTTP method(s) to match. Matches all methods if omitted. */
	method?: string | string[];
	/** Whether to require a valid auth token. Default: true */
	requireAuth?: boolean;
	requiredPermissions?: Array<{
		resource: string;
		actions: string[];
	}>;
	/**
	 * OAuth scopes the token must carry (MCP mode only). A shortfall gives a 403
	 * `insufficient_scope` challenge. Config validation rejects this field when
	 * the gateway has no `mcp` block, so a policy cannot silently do nothing.
	 */
	requiredScopes?: string[];
	rateLimit?: RateLimitConfig;
	/** Mark this path as public (no auth required, overrides requireAuth) */
	public?: boolean;
}

export interface GatewayConfig {
	upstream: string;
	/** Base path prefix for all proxied routes. Default: '/' */
	basePath?: string;
	theauth: TheAuth;
	policies?: GatewayPolicy[];
	cors?: CorsConfig;
	rateLimit?: RateLimitConfig;
	/** Record an audit entry for every request. Default: true */
	audit?: boolean;
	/**
	 * Remove the Authorization header before forwarding. Default: true. The
	 * token was issued for the gateway, so the upstream has no business seeing
	 * it (a compromised or logging upstream could replay it). Set false only
	 * when the upstream needs the same token.
	 */
	stripAuthHeader?: boolean;
	/**
	 * MCP mode. Validates OAuth 2.1 access tokens through the MCP resource
	 * validation (audience, optional DPoP, scopes), serves RFC 9728 protected
	 * resource metadata for the upstream and adds `resource_metadata` to every
	 * 401. Without it the gateway validates TheAuth agent tokens.
	 */
	mcp?: GatewayMcpConfig;
	/** Largest accepted request body in bytes. Default: 10 MiB. Over it gives 413. */
	maxBodyBytes?: number;
	/**
	 * Milliseconds to wait for the upstream to start responding (headers).
	 * Default: 30000. It does not cut off a stream already flowing, so SSE and
	 * long streamable HTTP responses are not affected.
	 */
	upstreamTimeoutMs?: number;
	/**
	 * How to find the client IP behind your proxies. Default: forwarded headers
	 * are ignored, so the IP is unknown (ip allowlist constraints deny and
	 * unauthenticated rate limiting falls back to a request fingerprint). Set
	 * `trustedProxyCount` or `trustedHeader` to match your deployment.
	 */
	trustedProxy?: TrustedProxyConfig;
}

export interface GatewayMcpConfig {
	/**
	 * The MCP auth module from `createMcpModule`. Only `requireMcpAuth` and
	 * `getProtectedResourceMetadata` are used, so it may be a validation-only
	 * module that shares the signing key with your authorization server.
	 */
	auth: Pick<McpAuthModule, "requireMcpAuth" | "getProtectedResourceMetadata">;
	/**
	 * Public URL clients use to reach the MCP endpoint through the gateway, for
	 * example `https://mcp.example.com/mcp`. It is the token audience (RFC 8707)
	 * and the `resource` in the metadata document.
	 */
	resource: string;
	requiredScopes?: string[];
	resourceMetadataUrl?: string;
}

export interface Gateway {
	handleRequest(request: Request): Promise<Response>;
	listen(port: number): Promise<void>;
	close(): Promise<void>;
}

export interface ResolvedIdentity {
	agentId: string;
	ownerId: string;
	token: string;
	kind: "agent-token" | "mcp";
	/** Set in MCP mode when the token carries an agent claim. */
	mcpAgentId?: string;
}

export interface RateLimitEntry {
	timestamps: number[];
}
