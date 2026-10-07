import { json } from "./helpers.js";
import type { EndpointContext, PluginEndpoint } from "./types.js";

/**
 * Match a URL pathname against a route pattern that may contain colon params.
 *
 * Returns a record of captured param values when matched, or null when the
 * pattern does not match the path.
 *
 * @example
 * matchPath('/auth/verify/:token', '/auth/verify/abc123')
 * // => { token: 'abc123' }
 */
function matchPath(pattern: string, pathname: string): Record<string, string> | null {
	const patternParts = pattern.split("/");
	const pathParts = pathname.split("/");

	if (patternParts.length !== pathParts.length) return null;

	const params: Record<string, string> = {};

	for (let i = 0; i < patternParts.length; i++) {
		const patternPart = patternParts[i];
		const pathPart = pathParts[i];

		if (patternPart === undefined || pathPart === undefined) return null;

		if (patternPart.startsWith(":")) {
			// Colon param — capture the value
			const paramName = patternPart.slice(1);
			params[paramName] = decodeURIComponent(pathPart);
		} else if (patternPart !== pathPart) {
			// Literal segment mismatch
			return null;
		}
	}

	return params;
}

/**
 * Create a plugin router that matches requests to registered plugin endpoints.
 *
 * The router strips `basePath` from the request URL before matching so plugins
 * register paths relative to the mount point (e.g. `/auth/sign-in` instead
 * of `/api/theauth/auth/sign-in`).
 */
export function createPluginRouter(endpoints: PluginEndpoint[]): {
	/** Try to handle a request. Returns Response if matched, null if not. */
	handle: (
		request: Request,
		basePath: string,
		endpointCtx: EndpointContext,
	) => Promise<Response | null>;
	/** Get all registered endpoints (for adapter mounting) */
	getEndpoints: () => PluginEndpoint[];
} {
	const rateLimitStore = new Map<string, { count: number; resetAt: number }>();

	function checkRateLimit(key: string, windowSeconds: number, max: number): boolean {
		const now = Date.now();
		const entry = rateLimitStore.get(key);

		if (!entry || now > entry.resetAt) {
			rateLimitStore.set(key, { count: 1, resetAt: now + windowSeconds * 1000 });
			return true;
		}

		if (entry.count >= max) return false;
		entry.count++;
		return true;
	}

	return {
		async handle(
			request: Request,
			basePath: string,
			endpointCtx: EndpointContext,
		): Promise<Response | null> {
			const url = new URL(request.url);
			let pathname = url.pathname;

			// Strip basePath prefix, normalising trailing slash differences
			const base = basePath.endsWith("/") ? basePath.slice(0, -1) : basePath;
			if (base && pathname.startsWith(base)) {
				pathname = pathname.slice(base.length) || "/";
			}

			// Normalise: ensure single leading slash, no trailing slash (except root)
			if (!pathname.startsWith("/")) {
				pathname = `/${pathname}`;
			}
			if (pathname.length > 1 && pathname.endsWith("/")) {
				pathname = pathname.slice(0, -1);
			}

			const method = request.method.toUpperCase() as PluginEndpoint["method"];

			for (const endpoint of endpoints) {
				if (endpoint.method !== method) continue;

				const params = matchPath(endpoint.path, pathname);
				if (params === null) continue;

				// --- Rate limit enforcement ---
				if (endpoint.metadata?.rateLimit) {
					const { window: windowSec, max } = endpoint.metadata.rateLimit;
					const ip =
						request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ??
						request.headers.get("x-real-ip") ??
						"unknown";
					const key = `${ip}:${endpoint.path}`;
					if (!checkRateLimit(key, windowSec, max)) {
						return json({ error: "Rate limit exceeded" }, 429);
					}
				}

				// --- Auth enforcement ---
				if (endpoint.metadata?.requireAuth) {
					const user = await endpointCtx.getUser(request);
					if (!user) {
						return json({ error: "Authentication required" }, 401);
					}
				}

				// Attach matched path params to the request URL so handlers can read
				// them via `new URL(request.url).searchParams` or a dedicated helper.
				// We inject them as search params prefixed with `_param_` to avoid
				// collisions with real query params while keeping this zero-dep.
				const enrichedUrl = new URL(request.url);
				for (const [key, value] of Object.entries(params)) {
					enrichedUrl.searchParams.set(`_param_${key}`, value);
				}

				const enrichedRequest = new Request(enrichedUrl.toString(), request);

				return endpoint.handler(enrichedRequest, endpointCtx);
			}

			return null;
		},

		getEndpoints(): PluginEndpoint[] {
			return [...endpoints];
		},
	};
}
