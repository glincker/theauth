import type { Kavach } from "@glinr/theauth";
import type { McpAuthModule } from "@glinr/theauth/mcp";
import { dispatch } from "./dispatch.js";

export interface KavachTanStackOptions {
	/**
	 * The MCP OAuth 2.1 module. When provided, MCP endpoints are enabled.
	 */
	mcp?: McpAuthModule;
	/**
	 * The URL path prefix before the `$` splat segment.
	 * Defaults to `/api/kavach`.
	 *
	 * @example `/api/auth/kavach`
	 */
	basePath?: string;
}

export interface KavachTanStackHandlers {
	GET: (request: Request) => Promise<Response>;
	POST: (request: Request) => Promise<Response>;
	PATCH: (request: Request) => Promise<Response>;
	DELETE: (request: Request) => Promise<Response>;
	OPTIONS: (request: Request) => Promise<Response>;
}

/**
 * Create TanStack Start API route handlers for all TheAuth REST API routes.
 *
 * Mount in `app/routes/api/kavach.$.ts`:
 *
 * @example
 * ```typescript
 * import { createKavach } from '@glinr/theauth';
 * import { kavachTanStack } from '@glinr/theauth-tanstack';
 *
 * const kavach = createKavach({ database: { provider: 'sqlite', url: 'kavach.db' } });
 * const handlers = kavachTanStack(kavach);
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
 * const handlers = kavachTanStack(kavach, { mcp });
 * ```
 */
export function kavachTanStack(
	kavach: Kavach,
	options?: KavachTanStackOptions,
): KavachTanStackHandlers {
	const mcp = options?.mcp;
	const basePath = options?.basePath ?? "/api/kavach";

	// TanStack Start API routes receive a standard Web API Request, so we can
	// pass it directly to the TheAuth dispatcher without any conversion.
	const handler = (request: Request): Promise<Response> => dispatch(request, kavach, mcp, basePath);

	return {
		GET: handler,
		POST: handler,
		PATCH: handler,
		DELETE: handler,
		OPTIONS: handler,
	};
}
