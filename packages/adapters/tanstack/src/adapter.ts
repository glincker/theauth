import type { AdapterSecurityOptions, TheAuth } from "@glinr/theauth";
import { createAdapterGuard } from "@glinr/theauth";
import type { McpAuthModule } from "@glinr/theauth/mcp";
import { dispatch } from "./dispatch.js";

export interface TheAuthTanStackOptions extends AdapterSecurityOptions {
	/**
	 * The MCP OAuth 2.1 module. When provided, MCP endpoints are enabled.
	 */
	mcp?: McpAuthModule;
	/**
	 * The URL path prefix before the `$` splat segment.
	 * Defaults to `/api/theauth`.
	 *
	 * @example `/api/auth/theauth`
	 */
	basePath?: string;
}

export interface TheAuthTanStackHandlers {
	GET: (request: Request) => Promise<Response>;
	POST: (request: Request) => Promise<Response>;
	PATCH: (request: Request) => Promise<Response>;
	DELETE: (request: Request) => Promise<Response>;
	OPTIONS: (request: Request) => Promise<Response>;
}

/** @deprecated Use `TheAuthTanStackOptions` instead. Will be removed in a future major version. */
export type AuthTanStackOptions = TheAuthTanStackOptions;

/** @deprecated Use `TheAuthTanStackHandlers` instead. Will be removed in a future major version. */
export type AuthTanStackHandlers = TheAuthTanStackHandlers;

/**
 * Create TanStack Start API route handlers for all TheAuth REST API routes.
 *
 * Mount in `app/routes/api/auth.$.ts`:
 *
 * @example
 * ```typescript
 * import { createTheAuth } from '@glinr/theauth';
 * import { theAuthTanStack } from '@glinr/theauth-tanstack';
 *
 * const auth = createTheAuth({ database: { provider: 'sqlite', url: 'theauth.db' } });
 * const handlers = theAuthTanStack(auth);
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
 * const handlers = theAuthTanStack(auth, { mcp });
 * ```
 */
export function theAuthTanStack(
	auth: TheAuth,
	options?: TheAuthTanStackOptions,
): TheAuthTanStackHandlers {
	const mcp = options?.mcp;
	const basePath = options?.basePath ?? "/api/theauth";
	// Fails closed at construction when nothing can authenticate callers.
	const guard = createAdapterGuard(auth, options, "theAuthTanStack");

	// TanStack Start API routes receive a standard Web API Request, so we can
	// pass it directly to the TheAuth dispatcher without any conversion.
	const handler = (request: Request): Promise<Response> =>
		dispatch(request, auth, mcp, basePath, guard);

	return {
		GET: handler,
		POST: handler,
		PATCH: handler,
		DELETE: handler,
		OPTIONS: handler,
	};
}

/** @deprecated Use `theAuthTanStack` instead. Will be removed in a future major version. */
export const authTanStack = theAuthTanStack;
