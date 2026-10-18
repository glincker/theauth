import type { TheAuth } from "@glinr/theauth";
import type { TheAuthHandlerOptions } from "@glinr/theauth/http";
import { createTheAuthHandler } from "@glinr/theauth/http";

/** Same options as the core handler: `mcp`, `basePath`, `routes`, `maxBodyBytes` plus the shared security options. */
export type TheAuthTanStackOptions = TheAuthHandlerOptions;

/** What a TanStack route receives: the server route context (has `request`), or a bare `Request`. */
export interface TanStackEventLike {
	request: Request;
	context?: Record<string, unknown>;
}
export type TanStackInput = Request | TanStackEventLike;

export type TanStackRouteHandler = (input: TanStackInput) => Promise<Response>;

export interface TheAuthTanStackHandlers {
	GET: TanStackRouteHandler;
	POST: TanStackRouteHandler;
	PATCH: TanStackRouteHandler;
	DELETE: TanStackRouteHandler;
	OPTIONS: TanStackRouteHandler;
}

/** The Request inside a TanStack event, or the Request itself. */
export function requestOf(input: TanStackInput): Request {
	return input instanceof Request ? input : input.request;
}

/**
 * Create TanStack API route handlers for all TheAuth REST API routes.
 * Mount in `src/routes/api/theauth/[...auth].ts`:
 *
 * @example
 * ```typescript
 * export const { GET, POST, PATCH, DELETE, OPTIONS } = theAuthTanStack(auth, { mcp });
 * ```
 */
export function theAuthTanStack(
	auth: TheAuth,
	options?: TheAuthTanStackOptions,
): TheAuthTanStackHandlers {
	const handle = createTheAuthHandler(auth, options);
	const handler: TanStackRouteHandler = (input) => handle(requestOf(input));
	return { GET: handler, POST: handler, PATCH: handler, DELETE: handler, OPTIONS: handler };
}
