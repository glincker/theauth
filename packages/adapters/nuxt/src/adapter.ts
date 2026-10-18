import type { TheAuth } from "@glinr/theauth";
import type { TheAuthHandlerOptions } from "@glinr/theauth/http";
import { createTheAuthHandler } from "@glinr/theauth/http";
import type { EventHandler } from "h3";
import { defineEventHandler, toWebRequest } from "h3";

/** Same options as the core handler: `mcp`, `basePath`, `routes`, `maxBodyBytes` plus the shared security options. */
export type TheAuthNuxtOptions = TheAuthHandlerOptions;

/**
 * Create a Nuxt/H3 event handler for all TheAuth REST API routes.
 * Mount in `server/api/theauth/[...].ts`:
 *
 * @example
 * ```typescript
 * export default theAuthNuxt(auth, { mcp, authenticate });
 * ```
 */
export function theAuthNuxt(auth: TheAuth, options?: TheAuthNuxtOptions): EventHandler {
	const handle = createTheAuthHandler(auth, options);
	// h3 sends a returned web Response as is, including repeated Set-Cookie headers.
	return defineEventHandler((event) => handle(toWebRequest(event)));
}
