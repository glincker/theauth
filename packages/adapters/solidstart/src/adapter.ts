import type { Kavach } from "@glinr/theauth";
import type { McpAuthModule } from "@glinr/theauth/mcp";
import { dispatch } from "./dispatch.js";

export interface KavachSolidStartOptions {
	/**
	 * The MCP OAuth 2.1 module. When provided, MCP endpoints are enabled.
	 */
	mcp?: McpAuthModule;
	/**
	 * The URL path prefix before the `[...kavach]` catch-all segment.
	 * Defaults to `/api/kavach`.
	 *
	 * @example `/api/auth/kavach`
	 */
	basePath?: string;
}

export interface KavachSolidStartHandlers {
	GET: (request: Request) => Promise<Response>;
	POST: (request: Request) => Promise<Response>;
	PATCH: (request: Request) => Promise<Response>;
	DELETE: (request: Request) => Promise<Response>;
	OPTIONS: (request: Request) => Promise<Response>;
}

/**
 * Create SolidStart API route handlers for all TheAuth REST API routes.
 *
 * Mount in `src/routes/api/kavach/[...kavach].ts`:
 *
 * @example
 * ```typescript
 * import { createKavach } from '@glinr/theauth';
 * import { kavachSolidStart } from '@glinr/theauth-solidstart';
 *
 * const kavach = createKavach({ database: { provider: 'sqlite', url: 'kavach.db' } });
 * const handlers = kavachSolidStart(kavach);
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
 * const handlers = kavachSolidStart(kavach, { mcp });
 * ```
 */
export function kavachSolidStart(
	kavach: Kavach,
	options?: KavachSolidStartOptions,
): KavachSolidStartHandlers {
	const mcp = options?.mcp;
	const basePath = options?.basePath ?? "/api/kavach";

	// SolidStart API routes receive a standard Web API Request, so we can pass
	// it directly to the TheAuth dispatcher without any conversion.
	const handler = (request: Request): Promise<Response> => dispatch(request, kavach, mcp, basePath);

	return {
		GET: handler,
		POST: handler,
		PATCH: handler,
		DELETE: handler,
		OPTIONS: handler,
	};
}
