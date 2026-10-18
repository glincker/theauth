import type { ZodTypeAny } from "zod";
import type { AdapterSecurityOptions } from "../adapter-guard.js";
import type { AdapterScope } from "../adapter-scope.js";
import type { McpMountedRoutes } from "../mcp/metadata.js";
import type { McpAuthModule } from "../mcp/types.js";
import type { TheAuth } from "../theauth-core.js";

/** Options for {@link createTheAuthHandler}. Security options are the shared adapter ones (authenticate, allowUnauthenticated, trustedProxy, rateLimit, trustedOrigins, csrf). */
export interface TheAuthHandlerOptions extends AdapterSecurityOptions {
	/** MCP OAuth module. Without it the MCP and well-known routes answer 404. */
	mcp?: McpAuthModule;
	/** URL prefix the handler is mounted under. Default `/api/theauth`. */
	basePath?: string;
	/** Turn route groups off. Each defaults to on. `mcp` also takes a partial set to mount only some MCP endpoints (the metadata then lists only those). */
	routes?: {
		management?: boolean;
		mcp?: boolean | Partial<McpMountedRoutes>;
		plugins?: boolean;
		explain?: boolean;
	};
	/** Largest accepted request body in bytes. Default 1048576 (1 MiB). Larger bodies get 413. */
	maxBodyBytes?: number;
}

export type TheAuthHandler = (request: Request) => Promise<Response>;

export type RouteAuthLevel = "admin" | "agent" | "client" | "public";

/** One served route. Also the input for generated documentation and OpenAPI. */
export interface RouteSpec {
	method: "GET" | "POST" | "PATCH" | "DELETE";
	/** Path relative to the base path. Parameters look like `:id`. */
	path: string;
	/**
	 * admin: a signed-in user (or your `authenticate` principal), limited to their own resources by default.
	 * agent: an agent bearer token.
	 * client: an OAuth client (credentials in the request).
	 * public: no credentials needed (the route does its own checks).
	 */
	auth: RouteAuthLevel;
	body?: ZodTypeAny;
	response?: ZodTypeAny;
	summary: string;
}

/** What a route handler receives. */
export interface RouteContext {
	auth: TheAuth;
	request: Request;
	url: URL;
	params: Record<string, string>;
	/** Set for `admin` routes. */
	scope: AdapterScope | null;
	clientIp: (request: Request) => string | null;
	mcp: McpAuthModule | undefined;
	mounted: McpMountedRoutes;
	maxBodyBytes: number;
}

export interface HttpRoute extends RouteSpec {
	/** Which option group turns this route off. */
	group: "management" | "mcp" | "explain";
	/** For MCP routes, the mounted-set key that gates it. */
	mcpRoute?: keyof McpMountedRoutes;
	handle: (ctx: RouteContext) => Promise<Response>;
}
