import type { TheAuth } from "@glinr/theauth";
import type { TheAuthHandlerOptions } from "@glinr/theauth/http";
import { createTheAuthHandler } from "@glinr/theauth/http";
import type { APIRoute } from "astro";

/** Same options as the core handler: `mcp`, `basePath`, `routes`, `maxBodyBytes` plus the shared security options. */
export type TheAuthAstroOptions = TheAuthHandlerOptions;

export interface TheAuthAstroHandlers {
	GET: APIRoute;
	POST: APIRoute;
	PATCH: APIRoute;
	DELETE: APIRoute;
	OPTIONS: APIRoute;
	ALL: APIRoute;
}

/**
 * Create Astro API route handlers for all TheAuth REST API routes.
 * Mount in `src/pages/api/theauth/[...path].ts`:
 *
 * @example
 * ```typescript
 * const handlers = theAuthAstro(auth, { mcp });
 * export const ALL = handlers.ALL;
 * ```
 */
export function theAuthAstro(auth: TheAuth, options?: TheAuthAstroOptions): TheAuthAstroHandlers {
	const handle = createTheAuthHandler(auth, options);
	// Astro already hands over a Web API Request.
	const handler: APIRoute = ({ request }) => handle(request);
	return {
		GET: handler,
		POST: handler,
		PATCH: handler,
		DELETE: handler,
		OPTIONS: handler,
		ALL: handler,
	};
}
