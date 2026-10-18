import type { TheAuth } from "@glinr/theauth";
import type { TheAuthHandlerOptions } from "@glinr/theauth/http";
import { createTheAuthHandler } from "@glinr/theauth/http";
import type { RequestHandler } from "@sveltejs/kit";

/** Same options as the core handler: `mcp`, `basePath`, `routes`, `maxBodyBytes` plus the shared security options. */
export type TheAuthSvelteKitOptions = TheAuthHandlerOptions;

export interface TheAuthSvelteKitHandlers {
	GET: RequestHandler;
	POST: RequestHandler;
	PATCH: RequestHandler;
	DELETE: RequestHandler;
	OPTIONS: RequestHandler;
}

/**
 * Create SvelteKit route handlers for all TheAuth REST API routes.
 * Mount in `src/routes/api/theauth/[...path]/+server.ts`:
 *
 * @example
 * ```typescript
 * export const { GET, POST, PATCH, DELETE, OPTIONS } = theAuthSvelteKit(auth, { mcp });
 * ```
 */
export function theAuthSvelteKit(
	auth: TheAuth,
	options?: TheAuthSvelteKitOptions,
): TheAuthSvelteKitHandlers {
	const handle = createTheAuthHandler(auth, options);
	// The SvelteKit event already hands over a Web API Request.
	const handler: RequestHandler = ({ request }) => handle(request);
	return { GET: handler, POST: handler, PATCH: handler, DELETE: handler, OPTIONS: handler };
}
