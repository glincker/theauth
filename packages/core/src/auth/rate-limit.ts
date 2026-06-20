/**
 * rateLimit() plugin for TheAuth.
 *
 * Wraps auth endpoints with configurable per-IP (and per-agent) throttling.
 * Intercepts requests via the onRequest lifecycle hook before any handler
 * runs, keeping the limiting logic decoupled from individual endpoints.
 *
 * @example
 * ```typescript
 * import { createKavach } from 'theauth';
 * import { rateLimit } from 'theauth/auth';
 * import { kvStore } from 'theauth/auth/stores/kv';
 *
 * const kavach = createKavach({
 *   plugins: [
 *     rateLimit({
 *       signIn:        { window: '15m', max: 10 },
 *       signUp:        { window: '1h',  max: 5  },
 *       passwordReset: { window: '1h',  max: 3  },
 *       agentAuthorize:{ window: '1m',  max: 100 },
 *       default:       { window: '1m',  max: 60  },
 *       store: kvStore(env.CACHE_KV),
 *     }),
 *   ],
 * });
 * ```
 */

import type { KavachPlugin } from "../plugin/types.js";
import { MemoryStore } from "./stores/memory.js";
import type { RateLimitStore } from "./stores/types.js";

// Re-export so consumers can import the interface from this module.
export type { RateLimitStore };

/** Per-endpoint rate limit configuration */
export interface EndpointLimit {
	/** Duration string: "15m", "1h", "30s", "1d" */
	window: string;
	/** Maximum number of requests allowed within the window */
	max: number;
}

export interface RateLimitConfig {
	/** Limit for POST /auth/sign-in */
	signIn?: EndpointLimit;
	/** Limit for POST /auth/sign-up */
	signUp?: EndpointLimit;
	/** Limit for POST /auth/password-reset */
	passwordReset?: EndpointLimit;
	/** Limit for POST /auth/agent/authorize */
	agentAuthorize?: EndpointLimit;
	/** Fallback limit applied to all other /auth/* paths */
	default?: EndpointLimit;
	/**
	 * Storage backend.
	 * Pass "memory" or omit to use the built-in in-memory store.
	 * Pass a KVStore (or any RateLimitStore) for edge deployments.
	 */
	store?: "memory" | RateLimitStore;
	/**
	 * Extract a rate-limit key from the request.
	 * Defaults to reading x-forwarded-for → x-real-ip → "unknown".
	 */
	keyExtractor?: (request: Request) => string;
	/**
	 * Custom response factory called when a limit is exceeded.
	 * Defaults to a JSON 429 response with Retry-After header.
	 */
	onLimit?: (request: Request, retryAfter: number) => Response;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Parse a window string like "15m", "1h", "30s", "1d" into milliseconds */
function parseWindowMs(window: string): number {
	const match = /^(\d+)(s|m|h|d)$/.exec(window);
	if (!match) {
		throw new Error(
			`Invalid rate limit window "${window}". Expected format: <number><s|m|h|d> e.g. "15m", "1h".`,
		);
	}
	const value = parseInt(match[1] ?? "0", 10);
	const unit = match[2];
	switch (unit) {
		case "s":
			return value * 1_000;
		case "m":
			return value * 60_000;
		case "h":
			return value * 3_600_000;
		case "d":
			return value * 86_400_000;
		default:
			throw new Error(`Unknown time unit "${unit}"`);
	}
}

function defaultKeyExtractor(request: Request): string {
	const forwarded = request.headers.get("x-forwarded-for");
	if (forwarded) {
		const first = (forwarded.split(",")[0] ?? "").trim();
		if (first) return first;
	}
	const real = request.headers.get("x-real-ip");
	if (real) return real.trim();
	return "unknown";
}

function defaultOnLimit(_request: Request, retryAfter: number): Response {
	return new Response(
		JSON.stringify({ error: { code: "RATE_LIMITED", message: "Too many requests" } }),
		{
			status: 429,
			headers: {
				"Content-Type": "application/json",
				"Retry-After": String(retryAfter),
			},
		},
	);
}

/** Map auth endpoint path suffixes to config keys */
const PATH_TO_CONFIG_KEY: Array<
	[string, keyof Omit<RateLimitConfig, "store" | "keyExtractor" | "onLimit" | "default">]
> = [
	["/auth/sign-in", "signIn"],
	["/auth/sign-up", "signUp"],
	["/auth/password-reset", "passwordReset"],
	["/auth/agent/authorize", "agentAuthorize"],
];

function resolveLimit(pathname: string, config: RateLimitConfig): EndpointLimit | undefined {
	for (const [suffix, key] of PATH_TO_CONFIG_KEY) {
		if (pathname === suffix || pathname.endsWith(suffix)) {
			const limit = config[key];
			if (limit) return limit;
		}
	}
	return config.default;
}

// ---------------------------------------------------------------------------
// Plugin factory
// ---------------------------------------------------------------------------

export function rateLimit(config: RateLimitConfig = {}): KavachPlugin {
	const store: RateLimitStore =
		!config.store || config.store === "memory" ? new MemoryStore() : config.store;

	const extractKey = config.keyExtractor ?? defaultKeyExtractor;
	const onLimitFn = config.onLimit ?? defaultOnLimit;

	return {
		id: "kavach-rate-limit",

		hooks: {
			async onRequest(request: Request): Promise<Request | Response | undefined> {
				const url = new URL(request.url);
				const pathname = url.pathname;

				// Only intercept /auth/* paths
				if (!pathname.includes("/auth/")) {
					return undefined;
				}

				const limit = resolveLimit(pathname, config);
				if (!limit) {
					return undefined;
				}

				const windowMs = parseWindowMs(limit.window);
				const key = `rate-limit:${pathname}:${extractKey(request)}`;

				const { count, resetAt } = await store.increment(key, windowMs);

				if (count > limit.max) {
					const retryAfterMs = Math.max(resetAt - Date.now(), 0);
					const retryAfterSeconds = Math.ceil(retryAfterMs / 1000);
					const response = onLimitFn(request, Math.max(retryAfterSeconds, 1));

					// Clone and augment the response with rate limit headers
					const headers = new Headers(response.headers);
					headers.set("X-RateLimit-Limit", String(limit.max));
					headers.set("X-RateLimit-Remaining", "0");
					headers.set("X-RateLimit-Reset", String(Math.ceil(resetAt / 1000)));
					headers.set("Retry-After", String(Math.max(retryAfterSeconds, 1)));

					return new Response(response.body, {
						status: response.status,
						headers,
					});
				}

				// Under the limit — let the request through but we can't attach headers
				// to the request itself. Headers on successful responses are attached by
				// callers that wrap individual handlers. The plugin approach intercepts
				// at the request level, so we pass through.
				return undefined;
			},
		},
	};
}
