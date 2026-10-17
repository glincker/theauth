import type { AdapterSecurityOptions, TheAuth } from "@glinr/theauth";
import { createAdapterGuard } from "@glinr/theauth";
import type { McpAuthModule } from "@glinr/theauth/mcp";
import type { EventHandler, H3Event } from "h3";
import { defineEventHandler, getRequestURL, readBody, setHeader, setResponseStatus } from "h3";
import { dispatch } from "./dispatch.js";

export interface TheAuthNuxtOptions extends AdapterSecurityOptions {
	mcp?: McpAuthModule;
	/** URL path prefix before the catch-all segment. Defaults to `/api/theauth`. */
	basePath?: string;
}

/** @deprecated Use `TheAuthNuxtOptions` instead. Will be removed in a future major version. */
export type AuthNuxtOptions = TheAuthNuxtOptions;

/**
 * Create a Nuxt/H3 event handler for all TheAuth REST API routes.
 *
 * Mount in `server/api/theauth/[...].ts`:
 *
 * @example
 * ```typescript
 * import { createTheAuth } from '@glinr/theauth';
 * import { theAuthNuxt } from '@glinr/theauth-nuxt';
 *
 * const auth = createTheAuth({ database: { provider: 'sqlite', url: 'theauth.db' } });
 * export default theAuthNuxt(auth);
 * ```
 *
 * With MCP OAuth 2.1:
 * ```typescript
 * import { createMcpModule } from '@glinr/theauth/mcp';
 * const mcp = createMcpModule({ ... });
 * export default theAuthNuxt(auth, { mcp });
 * ```
 */
export function theAuthNuxt(auth: TheAuth, options?: TheAuthNuxtOptions): EventHandler {
	const mcp = options?.mcp;
	const basePath = options?.basePath ?? "/api/theauth";
	// Fails closed at construction when nothing can authenticate callers.
	const guard = createAdapterGuard(auth, options, "theAuthNuxt");

	return defineEventHandler(async (event: H3Event) => {
		// Build a standard Request from the H3 event so dispatch can be reused.
		const url = getRequestURL(event);
		const method = event.method ?? "GET";

		const headers = new Headers();
		const rawHeaders = event.headers;
		rawHeaders.forEach((value, key) => {
			headers.set(key, value);
		});

		// Re-serialise the H3 body as JSON so Request.json() in dispatch works.
		let body: BodyInit | null = null;
		if (method !== "GET" && method !== "HEAD" && method !== "OPTIONS") {
			try {
				const raw = await readBody(event);
				if (raw !== undefined && raw !== null) {
					body = JSON.stringify(raw);
					headers.set("Content-Type", "application/json");
				}
			} catch {
				// body stays null, dispatch will handle the parse error
			}
		}

		const request = new Request(url.toString(), { method, headers, body });
		const response = await dispatch(request, auth, mcp, basePath, guard);

		setResponseStatus(event, response.status);
		response.headers.forEach((value, key) => {
			if (key.toLowerCase() !== "set-cookie") setHeader(event, key, value);
		});
		// Headers.forEach folds repeated Set-Cookie into one comma-joined value.
		const cookies = response.headers.getSetCookie();
		if (cookies.length > 0) setHeader(event, "set-cookie", cookies);

		// H3 can send a string, Buffer or null, so return the text as-is.
		if (response.status === 204 || response.body === null) {
			return null;
		}
		return response.text();
	});
}

/** @deprecated Use `theAuthNuxt` instead. Will be removed in a future major version. */
export const authNuxt = theAuthNuxt;
