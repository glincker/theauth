import type { Kavach } from "@glinr/theauth";
import type { McpAuthModule } from "@glinr/theauth/mcp";
import { dispatch } from "./dispatch.js";

export interface AuthSolidStartOptions {
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

/** @deprecated Use {@link AuthSolidStartOptions} instead. Will be removed in v3.0. */
export type KavachSolidStartOptions = AuthSolidStartOptions;

export interface AuthSolidStartHandlers {
	GET: (request: Request) => Promise<Response>;
	POST: (request: Request) => Promise<Response>;
	PATCH: (request: Request) => Promise<Response>;
	DELETE: (request: Request) => Promise<Response>;
	OPTIONS: (request: Request) => Promise<Response>;
}

/** @deprecated Use {@link AuthSolidStartHandlers} instead. Will be removed in v3.0. */
export type KavachSolidStartHandlers = AuthSolidStartHandlers;

/**
 * Create SolidStart API route handlers for all TheAuth REST API routes.
 *
 * Mount in `src/routes/api/auth/[...auth].ts`:
 *
 * @example
 * ```typescript
 * import { createAuth } from '@glinr/theauth';
 * import { authSolidStart } from '@glinr/theauth-solidstart';
 *
 * const auth = createAuth({ database: { provider: 'sqlite', url: 'kavach.db' } });
 * const handlers = authSolidStart(auth);
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
 * const handlers = authSolidStart(auth, { mcp });
 * ```
 */
export function authSolidStart(
	kavach: Kavach,
	options?: AuthSolidStartOptions,
): AuthSolidStartHandlers {
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

/** @deprecated Use {@link authSolidStart} instead. Will be removed in v3.0. */
export const kavachSolidStart = authSolidStart;
