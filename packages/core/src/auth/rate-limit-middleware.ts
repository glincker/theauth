/**
 * Higher-order function that wraps a plugin endpoint handler with IP-based
 * rate limiting. When the limit is exceeded it responds with 429 and a
 * Retry-After header before the wrapped handler is ever called.
 */

import type { PluginEndpoint } from "../plugin/types.js";
import type { TrustedProxyConfig } from "./client-ip.js";
import { resolveClientIp } from "./client-ip.js";
import type { RateLimiter } from "./rate-limiter.js";

export interface RateLimitMiddlewareOptions extends TrustedProxyConfig {
	/**
	 * Derive the rate-limit key from the incoming request.
	 *
	 * Defaults to the client IP resolved with the same trusted-proxy rules as
	 * `rateLimit()`: forwarded headers are ignored unless `trustedProxyCount` or
	 * `trustedHeader` is set here or on `createTheAuth({ trustedProxy })`. With
	 * nothing trusted every caller shares the "unknown" bucket (fail closed).
	 */
	keyExtractor?: (request: Request) => string;
}

export function withRateLimit(
	handler: PluginEndpoint["handler"],
	limiter: RateLimiter,
	options?: RateLimitMiddlewareOptions,
): PluginEndpoint["handler"] {
	return async function rateLimitedHandler(request, ctx) {
		const key = options?.keyExtractor
			? options.keyExtractor(request)
			: (resolveClientIp(request, {
					trustedProxyCount: options?.trustedProxyCount ?? ctx?.trustedProxy?.trustedProxyCount,
					trustedHeader: options?.trustedHeader ?? ctx?.trustedProxy?.trustedHeader,
				}) ?? "unknown");
		const result = limiter.check(key);

		if (!result.allowed) {
			const retryAfter = Math.ceil((result.resetAt.getTime() - Date.now()) / 1000);
			return new Response(
				JSON.stringify({ error: { code: "RATE_LIMITED", message: "Too many requests" } }),
				{
					status: 429,
					headers: {
						"Content-Type": "application/json",
						"Retry-After": String(Math.max(retryAfter, 1)),
					},
				},
			);
		}

		return handler(request, ctx);
	};
}
