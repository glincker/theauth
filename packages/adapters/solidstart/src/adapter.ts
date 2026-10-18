import type { TheAuth } from "@glinr/theauth";
import type { TheAuthHandlerOptions } from "@glinr/theauth/http";
import { createTheAuthHandler } from "@glinr/theauth/http";

/** Same options as the core handler: `mcp`, `basePath`, `routes`, `maxBodyBytes` plus the shared security options. */
export type TheAuthSolidStartOptions = TheAuthHandlerOptions;

/** What a SolidStart route receives: the `APIEvent` (has `request`), or a bare `Request`. */
export interface SolidStartEventLike {
	request: Request;
	locals?: Record<string, unknown>;
}
export type SolidStartInput = Request | SolidStartEventLike;

export type SolidStartRouteHandler = (input: SolidStartInput) => Promise<Response>;

export interface TheAuthSolidStartHandlers {
	GET: SolidStartRouteHandler;
	POST: SolidStartRouteHandler;
	PATCH: SolidStartRouteHandler;
	DELETE: SolidStartRouteHandler;
	OPTIONS: SolidStartRouteHandler;
}

/** The Request inside a SolidStart event, or the Request itself. */
export function requestOf(input: SolidStartInput): Request {
	return input instanceof Request ? input : input.request;
}

/**
 * Create SolidStart API route handlers for all TheAuth REST API routes.
 * Mount in `src/routes/api/theauth/[...auth].ts`:
 *
 * @example
 * ```typescript
 * export const { GET, POST, PATCH, DELETE, OPTIONS } = theAuthSolidStart(auth, { mcp });
 * ```
 */
export function theAuthSolidStart(
	auth: TheAuth,
	options?: TheAuthSolidStartOptions,
): TheAuthSolidStartHandlers {
	const handle = createTheAuthHandler(auth, options);
	const handler: SolidStartRouteHandler = (input) => handle(requestOf(input));
	return { GET: handler, POST: handler, PATCH: handler, DELETE: handler, OPTIONS: handler };
}
