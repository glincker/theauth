import type { RequestHandler } from "@sveltejs/kit";
import type { Kavach } from "theauth";
import type { McpAuthModule } from "theauth/mcp";
import { dispatch } from "./dispatch.js";

export interface KavachSvelteKitOptions {
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

export interface KavachSvelteKitHandlers {
	GET: RequestHandler;
	POST: RequestHandler;
	PATCH: RequestHandler;
	DELETE: RequestHandler;
	OPTIONS: RequestHandler;
}

/**
 * Create SvelteKit route handlers for all TheAuth REST API routes.
 *
 * Mount in `src/routes/api/kavach/[...path]/+server.ts`:
 *
 * @example
 * ```typescript
 * import { createKavach } from 'theauth';
 * import { kavachSvelteKit } from '@theauth/sveltekit';
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
 * import { createMcpModule } from 'theauth/mcp';
 * const mcp = createMcpModule({ ... });
 * const handlers = kavachSvelteKit(kavach, { mcp });
 * ```
 */
export function kavachSvelteKit(
	kavach: Kavach,
	options?: KavachSvelteKitOptions,
): KavachSvelteKitHandlers {
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
