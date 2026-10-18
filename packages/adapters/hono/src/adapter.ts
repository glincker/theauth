import type { TheAuth } from "@glinr/theauth";
import type { TheAuthHandler, TheAuthHandlerOptions } from "@glinr/theauth/http";
import { createTheAuthHandler } from "@glinr/theauth/http";
import { Hono } from "hono";

/** Options for {@link theAuthHono}: the core handler options (`mcp`, `basePath`, `routes`, `maxBodyBytes`, and the security options). */
export type TheAuthHonoOptions = TheAuthHandlerOptions;

/**
 * Mount every theAuth route on a Hono app. The app serves paths relative to where you
 * mount it (`app.route("/api/theauth", theAuthHono(auth))`) unless you pass `basePath`.
 *
 * @example
 * ```typescript
 * const app = new Hono();
 * app.route("/api/theauth", theAuthHono(auth, { mcp }));
 * ```
 */
export function theAuthHono(auth: TheAuth, options?: TheAuthHonoOptions): Hono {
	const app = new Hono();
	// Built now so an unsafe config fails at startup. Used when the mount point is the root.
	const handlers = new Map<string, TheAuthHandler>([
		[
			options?.basePath ?? "",
			createTheAuthHandler(auth, { ...options, basePath: options?.basePath ?? "" }),
		],
	]);

	app.all("*", (c) => {
		// The mount point of this app, for example "/api/theauth" from the route "/api/theauth/*".
		const mount = options?.basePath ?? c.req.routePath.replace(/\/?\*$/, "");
		let handler = handlers.get(mount);
		if (!handler) {
			handler = createTheAuthHandler(auth, { ...options, basePath: mount });
			handlers.set(mount, handler);
		}
		return handler(c.req.raw);
	});
	return app;
}
