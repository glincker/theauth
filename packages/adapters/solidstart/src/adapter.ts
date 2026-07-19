import type { TheAuth } from "@glinr/theauth";
import type { McpAuthModule } from "@glinr/theauth/mcp";
import { dispatch } from "./dispatch.js";

export interface TheAuthSolidStartOptions {
	/**
	 * The MCP OAuth 2.1 module. When provided, MCP endpoints are enabled.
	 */
	mcp?: McpAuthModule;
	/**
	 * The URL path prefix before the `[...auth]` catch-all segment.
	 * Defaults to `/api/kavach`.
	 *
	 * @example `/api/auth`
	 */
	basePath?: string;
}

/** @deprecated Use `TheAuthSolidStartOptions` instead. Will be removed in a future major version. */
export type AuthSolidStartOptions = TheAuthSolidStartOptions;

/** @deprecated Use `TheAuthSolidStartOptions` instead. Will be removed in a future major version. */
export type KavachSolidStartOptions = TheAuthSolidStartOptions;

export interface TheAuthSolidStartHandlers {
	GET: (request: Request) => Promise<Response>;
	POST: (request: Request) => Promise<Response>;
	PATCH: (request: Request) => Promise<Response>;
	DELETE: (request: Request) => Promise<Response>;
	OPTIONS: (request: Request) => Promise<Response>;
}

/** @deprecated Use `TheAuthSolidStartHandlers` instead. Will be removed in a future major version. */
export type AuthSolidStartHandlers = TheAuthSolidStartHandlers;

/** @deprecated Use `TheAuthSolidStartHandlers` instead. Will be removed in a future major version. */
export type KavachSolidStartHandlers = TheAuthSolidStartHandlers;

/**
 * Create SolidStart API route handlers for all TheAuth REST API routes.
 *
 * Mount in `src/routes/api/auth/[...auth].ts`:
 *
 * @example
 * ```typescript
 * import { createTheAuth } from '@glinr/theauth';
 * import { theAuthSolidStart } from '@glinr/theauth-solidstart';
 *
 * const auth = createTheAuth({ database: { provider: 'sqlite', url: 'kavach.db' } });
 * const handlers = theAuthSolidStart(auth);
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
 * const handlers = theAuthSolidStart(auth, { mcp });
 * ```
 */
export function theAuthSolidStart(
	auth: TheAuth,
	options?: TheAuthSolidStartOptions,
): TheAuthSolidStartHandlers {
	const mcp = options?.mcp;
	const basePath = options?.basePath ?? "/api/kavach";

	// SolidStart API routes receive a standard Web API Request, so we can pass
	// it directly to the TheAuth dispatcher without any conversion.
	const handler = (request: Request): Promise<Response> => dispatch(request, auth, mcp, basePath);

	return {
		GET: handler,
		POST: handler,
		PATCH: handler,
		DELETE: handler,
		OPTIONS: handler,
	};
}

/** @deprecated Use `theAuthSolidStart` instead. Will be removed in a future major version. */
export const authSolidStart = theAuthSolidStart;

/** @deprecated Use `theAuthSolidStart` instead. Will be removed in a future major version. */
export const kavachSolidStart = theAuthSolidStart;
