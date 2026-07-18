import type { TheAuth } from "@glinr/theauth";
import type { McpAuthModule } from "@glinr/theauth/mcp";
import type { EventHandler, H3Event } from "h3";
import { defineEventHandler, getRequestURL, readBody, setHeader, setResponseStatus } from "h3";
import { dispatch } from "./dispatch.js";

export interface KavachNuxtOptions {
	/**
	 * The MCP OAuth 2.1 module. When provided, MCP endpoints are enabled.
	 */
	mcp?: McpAuthModule;
	/**
	 * The URL path prefix before the catch-all segment.
	 * Defaults to `/api/kavach`.
	 *
	 * @example `/api/auth/kavach`
	 */
	basePath?: string;
}

/**
 * Create a Nuxt/H3 event handler for all TheAuth REST API routes.
 *
 * Mount in `server/api/kavach/[...].ts`:
 *
 * @example
 * ```typescript
 * import { createTheAuth } from '@glinr/theauth';
 * import { kavachNuxt } from '@glinr/theauth-nuxt';
 *
 * const kavach = createTheAuth({ database: { provider: 'sqlite', url: 'kavach.db' } });
 * export default kavachNuxt(kavach);
 * ```
 *
 * With MCP OAuth 2.1:
 * ```typescript
 * import { createMcpModule } from '@glinr/theauth/mcp';
 * const mcp = createMcpModule({ ... });
 * export default kavachNuxt(kavach, { mcp });
 * ```
 */
export function kavachNuxt(kavach: TheAuth, options?: KavachNuxtOptions): EventHandler {
	const mcp = options?.mcp;
	const basePath = options?.basePath ?? "/api/kavach";

	return defineEventHandler(async (event: H3Event) => {
		// Build a standard Request from the H3 event so we can delegate to the
		// shared dispatcher without duplicating any routing logic.
		const url = getRequestURL(event);
		const method = event.method ?? "GET";

		// Collect headers from the H3 event
		const headers = new Headers();
		const rawHeaders = event.headers;
		rawHeaders.forEach((value, key) => {
			headers.set(key, value);
		});

		// For methods that carry a body, read it from H3 and re-serialise as JSON
		// so the standard Request.json() call in dispatch works correctly.
		let body: BodyInit | null = null;
		if (method !== "GET" && method !== "HEAD" && method !== "OPTIONS") {
			try {
				const raw = await readBody(event);
				if (raw !== undefined && raw !== null) {
					body = JSON.stringify(raw);
					headers.set("Content-Type", "application/json");
				}
			} catch {
				// body stays null — dispatch will handle the parse error
			}
		}

		const request = new Request(url.toString(), { method, headers, body });
		const response = await dispatch(request, kavach, mcp, basePath);

		// Write the Response back through H3
		setResponseStatus(event, response.status);
		response.headers.forEach((value, key) => {
			setHeader(event, key, value);
		});

		// H3 route handlers can return a string, Buffer, or null; return the
		// body text directly so H3 sends it as-is.
		if (response.status === 204 || response.body === null) {
			return null;
		}
		return response.text();
	});
}
