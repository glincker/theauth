import type { Kavach } from "@glinr/theauth";
import type { McpAuthModule } from "@glinr/theauth/mcp";
import type { RequestHandler } from "@sveltejs/kit";
import { dispatch } from "./dispatch.js";

export interface AuthSvelteKitOptions {
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

/** @deprecated Use {@link AuthSvelteKitOptions} instead. Will be removed in v3.0. */
export type KavachSvelteKitOptions = AuthSvelteKitOptions;

export interface AuthSvelteKitHandlers {
	GET: RequestHandler;
	POST: RequestHandler;
	PATCH: RequestHandler;
	DELETE: RequestHandler;
	OPTIONS: RequestHandler;
}

/** @deprecated Use {@link AuthSvelteKitHandlers} instead. Will be removed in v3.0. */
export type KavachSvelteKitHandlers = AuthSvelteKitHandlers;

/**
 * Create SvelteKit route handlers for all TheAuth REST API routes.
 *
 * Mount in `src/routes/api/kavach/[...path]/+server.ts`:
 *
 * @example
 * ```typescript
 * import { createKavach } from '@glinr/theauth';
 * import { kavachSvelteKit } from '@glinr/theauth-sveltekit';
 *
 * const kavach = createKavach({ database: { provider: 'sqlite', url: 'kavach.db' } });
 * const handlers = kavachSvelteKit(kavach);
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
 * const handlers = kavachSvelteKit(kavach, { mcp });
 * ```
 */
export function authSvelteKit(
	kavach: Kavach,
	options?: AuthSvelteKitOptions,
): AuthSvelteKitHandlers {
	const mcp = options?.mcp;
	const basePath = options?.basePath ?? "/api/kavach";

	// SvelteKit RequestHandler receives an event whose `request` property is a
	// standard Web API Request, so we can pass it directly to dispatch.
	const handler: RequestHandler = ({ request }) => dispatch(request, kavach, mcp, basePath);

	return {
		GET: handler,
		POST: handler,
		PATCH: handler,
		DELETE: handler,
		OPTIONS: handler,
	};
}

/** @deprecated Use {@link authSvelteKit} instead. Will be removed in v3.0. */
export const kavachSvelteKit = authSvelteKit;
