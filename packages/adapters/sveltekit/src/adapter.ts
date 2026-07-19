import type { TheAuth } from "@glinr/theauth";
import type { McpAuthModule } from "@glinr/theauth/mcp";
import type { RequestHandler } from "@sveltejs/kit";
import { dispatch } from "./dispatch.js";

export interface TheAuthSvelteKitOptions {
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

/** @deprecated Use `TheAuthSvelteKitOptions` instead. Will be removed in a future major version. */
export type AuthSvelteKitOptions = TheAuthSvelteKitOptions;

/** @deprecated Use `TheAuthSvelteKitOptions` instead. Will be removed in a future major version. */
export type KavachSvelteKitOptions = TheAuthSvelteKitOptions;

export interface TheAuthSvelteKitHandlers {
	GET: RequestHandler;
	POST: RequestHandler;
	PATCH: RequestHandler;
	DELETE: RequestHandler;
	OPTIONS: RequestHandler;
}

/** @deprecated Use `TheAuthSvelteKitHandlers` instead. Will be removed in a future major version. */
export type AuthSvelteKitHandlers = TheAuthSvelteKitHandlers;

/** @deprecated Use `TheAuthSvelteKitHandlers` instead. Will be removed in a future major version. */
export type KavachSvelteKitHandlers = TheAuthSvelteKitHandlers;

/**
 * Create SvelteKit route handlers for all TheAuth REST API routes.
 *
 * Mount in `src/routes/api/kavach/[...path]/+server.ts`:
 *
 * @example
 * ```typescript
 * import { createTheAuth } from '@glinr/theauth';
 * import { theAuthSvelteKit } from '@glinr/theauth-sveltekit';
 *
 * const auth = createTheAuth({ database: { provider: 'sqlite', url: 'kavach.db' } });
 * const handlers = theAuthSvelteKit(auth);
 *
 * export const GET = handlers.GET;
 * export const POST = handlers.POST;
 * export const PATCH = handlers.PATCH;
 * export const DELETE = handlers.DELETE;
 * export const OPTIONS = handlers.OPTIONS;
 * ```
 *
 * With MCP OAuth 2.1:
 * ```typescript
 * import { createMcpModule } from '@glinr/theauth/mcp';
 * const mcp = createMcpModule({ ... });
 * const handlers = theAuthSvelteKit(auth, { mcp });
 * ```
 */
export function theAuthSvelteKit(
	auth: TheAuth,
	options?: TheAuthSvelteKitOptions,
): TheAuthSvelteKitHandlers {
	const mcp = options?.mcp;
	const basePath = options?.basePath ?? "/api/kavach";

	// SvelteKit RequestHandler receives an event whose `request` property is a
	// standard Web API Request, so we can pass it directly to dispatch.
	const handler: RequestHandler = ({ request }) => dispatch(request, auth, mcp, basePath);

	return {
		GET: handler,
		POST: handler,
		PATCH: handler,
		DELETE: handler,
		OPTIONS: handler,
	};
}

/** @deprecated Use `theAuthSvelteKit` instead. Will be removed in a future major version. */
export const authSvelteKit = theAuthSvelteKit;

/** @deprecated Use `theAuthSvelteKit` instead. Will be removed in a future major version. */
export const kavachSvelteKit = theAuthSvelteKit;
