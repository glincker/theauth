/**
 * Request admission for the framework adapters: tiered rate limiting and a
 * cross-site check for cookie-authenticated writes. Runs before
 * authentication so an anonymous flood is refused cheaply.
 */

import type { TrustedProxyConfig } from "./auth/client-ip.js";
import { resolveClientIp } from "./auth/client-ip.js";
import type { RateLimitConfig, RateLimiter } from "./auth/rate-limiter.js";
import { createRateLimiter } from "./auth/rate-limiter.js";

/** Per-tier limits for the adapter routes. Each is requests per window (seconds). */
export interface AdapterRateLimitOptions {
	/** Token, registration and authorization endpoints. Default 30 per 60s. */
	strict?: RateLimitConfig;
	/** Other POST, PUT, PATCH and DELETE routes. Default 120 per 60s. */
	mutation?: RateLimitConfig;
	/** GET routes, including the dashboard. Default 300 per 60s. */
	read?: RateLimitConfig;
}

export interface AdapterAdmitOptions {
	/** `false` turns rate limiting off (for example when a gateway already does it). */
	rateLimit?: false | AdapterRateLimitOptions;
	/**
	 * Origins allowed to send cookie-authenticated writes, e.g.
	 * `["https://app.example.com"]`. The request's own origin is always allowed.
	 * Set this when a proxy rewrites the `Host` header.
	 */
	trustedOrigins?: string[];
	/** `false` turns the cross-site check off. */
	csrf?: boolean;
}

export interface AdapterAdmission {
	/** A 429 or 403 Response to send, or null when the request may proceed. */
	admit(request: Request, relativePath: string): Response | null;
}

const STRICT_PATHS = ["/mcp/token", "/mcp/register", "/mcp/authorize", "/authorize"];
const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

function json(status: number, code: string, message: string, headers?: HeadersInit): Response {
	return new Response(JSON.stringify({ error: { code, message } }), {
		status,
		headers: { "Content-Type": "application/json", ...headers },
	});
}

function tierOf(method: string, path: string): "strict" | "mutation" | "read" {
	const p = path.split("?")[0]?.toLowerCase() ?? "";
	if (STRICT_PATHS.some((s) => p === s || p.startsWith(`${s}/`))) return "strict";
	return SAFE_METHODS.has(method) ? "read" : "mutation";
}

/** Short non-cryptographic digest so raw credentials never sit in the limiter map. */
function digest(value: string): string {
	let h = 0x811c9dc5;
	for (let i = 0; i < value.length; i++) {
		h ^= value.charCodeAt(i);
		h = Math.imul(h, 0x01000193);
	}
	return (h >>> 0).toString(36);
}

function bucketKey(request: Request, proxy: TrustedProxyConfig | undefined): string {
	const ip = resolveClientIp(request, proxy);
	if (ip) return `ip:${ip}`;
	// Without a trusted proxy setting the IP is unknown. Split callers by their
	// credential so one noisy client does not exhaust a shared bucket.
	const cred = request.headers.get("authorization") ?? request.headers.get("cookie");
	return cred ? `cred:${digest(cred)}` : "unknown";
}

function originOf(value: string): string | null {
	try {
		return new URL(value).origin;
	} catch {
		return null;
	}
}

/** Cookie-authenticated unsafe request from another site, or null when fine. */
function crossSiteDenial(request: Request, trusted: Set<string>): Response | null {
	if (SAFE_METHODS.has(request.method.toUpperCase())) return null;
	// Bearer callers are not ambient-credential requests.
	if (request.headers.get("authorization")) return null;
	if (!request.headers.get("cookie")) return null;

	const deny = (): Response =>
		json(403, "CSRF_REJECTED", "Cross-site request rejected for a cookie session");

	const fetchSite = request.headers.get("sec-fetch-site");
	if (fetchSite === "same-origin" || fetchSite === "none") return null;

	const origin = request.headers.get("origin") ?? request.headers.get("referer");
	if (!origin) {
		// Browsers send Origin on cross-origin writes. Fetch metadata saying
		// cross-site with no Origin is still refused.
		return fetchSite === "cross-site" || fetchSite === "same-site" ? deny() : null;
	}
	const claimed = originOf(origin);
	if (!claimed) return deny();
	const own = originOf(request.url);
	if (claimed === own || trusted.has(claimed)) return null;
	return deny();
}

export function createAdapterAdmission(
	options: AdapterAdmitOptions | undefined,
	proxy: TrustedProxyConfig | undefined,
): AdapterAdmission {
	const limits = options?.rateLimit === false ? null : (options?.rateLimit ?? {});
	const limiters: Record<"strict" | "mutation" | "read", RateLimiter> | null = limits
		? {
				strict: createRateLimiter(limits.strict ?? { max: 30, window: 60 }),
				mutation: createRateLimiter(limits.mutation ?? { max: 120, window: 60 }),
				read: createRateLimiter(limits.read ?? { max: 300, window: 60 }),
			}
		: null;
	const trusted = new Set(
		(options?.trustedOrigins ?? []).map(originOf).filter((o): o is string => o !== null),
	);
	const csrf = options?.csrf !== false;

	return {
		admit(request, relativePath) {
			if (limiters) {
				const tier = tierOf(request.method.toUpperCase(), relativePath);
				const result = limiters[tier].check(`${tier}:${bucketKey(request, proxy)}`);
				if (!result.allowed) {
					const retry = Math.max(1, Math.ceil((result.resetAt.getTime() - Date.now()) / 1000));
					return json(429, "RATE_LIMITED", "Too many requests", { "Retry-After": String(retry) });
				}
			}
			return csrf ? crossSiteDenial(request, trusted) : null;
		},
	};
}
