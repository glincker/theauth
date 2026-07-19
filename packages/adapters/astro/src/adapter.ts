import type { TheAuth } from "@glinr/theauth";
import type { McpAuthModule } from "@glinr/theauth/mcp";
import type { APIRoute } from "astro";
import { dispatch } from "./dispatch.js";

export interface TheAuthAstroOptions {
	/**
	 * The MCP OAuth 2.1 module. When provided, MCP endpoints are enabled.
	 */
	mcp?: McpAuthModule;
	/**
	 * The URL path prefix before the `[...path]` catch-all segment.
	 * Defaults to `/api/kavach`.
	 *
	 * @example `/api/auth`
	 */
	basePath?: string;
}

/** @deprecated Use `TheAuthAstroOptions` instead. Will be removed in a future major version. */
export type AuthAstroOptions = TheAuthAstroOptions;

/** @deprecated Use `TheAuthAstroOptions` instead. Will be removed in a future major version. */
export type KavachAstroOptions = TheAuthAstroOptions;

export interface TheAuthAstroHandlers {
	GET: APIRoute;
	POST: APIRoute;
	PATCH: APIRoute;
	DELETE: APIRoute;
	OPTIONS: APIRoute;
	ALL: APIRoute;
}

/** @deprecated Use `TheAuthAstroHandlers` instead. Will be removed in a future major version. */
export type AuthAstroHandlers = TheAuthAstroHandlers;

/** @deprecated Use `TheAuthAstroHandlers` instead. Will be removed in a future major version. */
export type KavachAstroHandlers = TheAuthAstroHandlers;

/**
 * Create Astro API route handlers for all TheAuth REST API routes.
 *
 * Mount in `src/pages/api/kavach/[...path].ts`:
 *
 * @example
 * ```typescript
 * import { createTheAuth } from '@glinr/theauth';
 * import { theAuthAstro } from '@glinr/theauth-astro';
 *
 * const auth = createTheAuth({ database: { provider: 'sqlite', url: 'theauth.db' } });
 * const handlers = theAuthAstro(auth);
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
 * const handlers = theAuthAstro(auth, { mcp });
 * ```
 */
export function theAuthAstro(auth: TheAuth, options?: TheAuthAstroOptions): TheAuthAstroHandlers {
	const mcp = options?.mcp;
	const basePath = options?.basePath ?? "/api/kavach";

	// Astro APIRoute receives a context whose `request` property is a standard
	// Web API Request, so we can pass it directly to dispatch.
	const handler: APIRoute = ({ request }) => dispatch(request, auth, mcp, basePath);

	return {
		GET: handler,
		POST: handler,
		PATCH: handler,
		DELETE: handler,
		OPTIONS: handler,
		ALL: handler,
	};
}

/** @deprecated Use `theAuthAstro` instead. Will be removed in a future major version. */
export const authAstro = theAuthAstro;

/** @deprecated Use `theAuthAstro` instead. Will be removed in a future major version. */
export const kavachAstro = theAuthAstro;
