import type { TheAuth } from "@glinr/theauth";
import type { TheAuthHandlerOptions } from "@glinr/theauth/http";
import { createTheAuthHandler } from "@glinr/theauth/http";

/** Options for {@link theAuthNextjs}: the core handler options. `basePath` defaults to `/api/theauth`. */
export type TheAuthNextjsOptions = TheAuthHandlerOptions;

export interface TheAuthNextjsHandlers {
	GET: (request: Request) => Promise<Response>;
	POST: (request: Request) => Promise<Response>;
	PATCH: (request: Request) => Promise<Response>;
	DELETE: (request: Request) => Promise<Response>;
	OPTIONS: (request: Request) => Promise<Response>;
}

/**
 * Route handlers for every theAuth route. Mount in `app/api/theauth/[...theauth]/route.ts`:
 *
 * @example
 * ```typescript
 * const handlers = theAuthNextjs(auth, { mcp });
 * export const { GET, POST, PATCH, DELETE, OPTIONS } = handlers;
 * ```
 */
export function theAuthNextjs(
	auth: TheAuth,
	options?: TheAuthNextjsOptions,
): TheAuthNextjsHandlers {
	const handler = createTheAuthHandler(auth, options);
	return { GET: handler, POST: handler, PATCH: handler, DELETE: handler, OPTIONS: handler };
}
