import type { Kavach } from "@glinr/theauth";
import type { McpAuthModule } from "@glinr/theauth/mcp";
import type { APIRoute } from "astro";
import { dispatch } from "./dispatch.js";

export interface KavachAstroOptions {
	/**
	 * The MCP OAuth 2.1 module. When provided, MCP endpoints are enabled.
	 */
	mcp?: McpAuthModule;
	/**
	 * The URL path prefix before the `[...path]` catch-all segment.
	 * Defaults to `/api/kavach`.
	 *
	 * @example `/api/auth/kavach`
	 */
	basePath?: string;
}

export interface KavachAstroHandlers {
	GET: APIRoute;
	POST: APIRoute;
	PATCH: APIRoute;
	DELETE: APIRoute;
	OPTIONS: APIRoute;
	ALL: APIRoute;
}

/**
 * Create Astro API route handlers for all TheAuth REST API routes.
 *
 * Mount in `src/pages/api/kavach/[...path].ts`:
 *
 * @example
 * ```typescript
 * import { createKavach } from '@glinr/theauth';
 * import { kavachAstro } from '@glinr/theauth-astro';
 *
 * const kavach = createKavach({ database: { provider: 'sqlite', url: 'kavach.db' } });
 * const handlers = kavachAstro(kavach);
 *
 * export const GET = handlers.GET;
 * export const POST = handlers.POST;
 * export const PATCH = handlers.PATCH;
 * export const DELETE = handlers.DELETE;
 * export const OPTIONS = handlers.OPTIONS;
 * ```
 *
 * Or use the catch-all handler:
 * ```typescript
 * export const ALL = handlers.ALL;
 * ```
 *
 * With MCP OAuth 2.1:
 * ```typescript
 * import { createMcpModule } from '@glinr/theauth/mcp';
 * const mcp = createMcpModule({ ... });
 * const handlers = kavachAstro(kavach, { mcp });
 * ```
 */
export function kavachAstro(kavach: Kavach, options?: KavachAstroOptions): KavachAstroHandlers {
	const mcp = options?.mcp;
	const basePath = options?.basePath ?? "/api/kavach";

	// Astro APIRoute receives a context whose `request` property is a standard
	// Web API Request, so we can pass it directly to dispatch.
	const handler: APIRoute = ({ request }) => dispatch(request, kavach, mcp, basePath);

	return {
		GET: handler,
		POST: handler,
		PATCH: handler,
		DELETE: handler,
		OPTIONS: handler,
		ALL: handler,
	};
}
