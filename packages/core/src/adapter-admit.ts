/** Request admission for the framework adapters: tiered rate limiting and a cross-site check for cookie-authenticated writes. Runs before authentication so an anonymous flood is refused cheaply. */

import type { TrustedProxyConfig } from "./auth/client-ip.js";
import type { RateLimitConfig, RateLimiter } from "./auth/rate-limiter.js";
import { createRateLimiter } from "./auth/rate-limiter.js";
import { resolveRequestIp } from "./http/node.js";
import type { TheAuthLogger } from "./observability/types.js";
import type { SecondaryStorage } from "./storage/types.js";

/** Per-tier limits for the adapter routes. Each is requests per window (seconds). */
export interface AdapterRateLimitOptions {
	/** Token, registration and authorization endpoints. Default 30 per 60s. */
	strict?: RateLimitConfig;
	/** Other POST, PUT, PATCH and DELETE routes. Default 120 per 60s. */
	mutation?: RateLimitConfig;
	/** GET routes, including the dashboard. Default 300 per 60s. */
	read?: RateLimitConfig;
	/** Return true to leave a request out of rate limiting, e.g. a health check or traffic from your own network. The cross-site check still applies. */
	skip?: (request: Request, relativePath: string) => boolean;
	/** What to do when the shared counter store errors. `false` (default) lets the request through so a store outage never takes sign-in and sign-up down. `true` refuses it with a 503, so an attacker cannot disable throttling by breaking the store. Only applies when a secondary store is in use; the in-process limiter cannot fail. */
	failClosed?: boolean;
	/** Replace the default client key (the client IP, or one of three fixed fallback buckets when the IP is unknown: anonymous, cookie, authorization). Without `trustedProxy` or this option limits are NOT per client. Return null to fall back to the default for a request. */
	key?: (request: Request) => string | null;
}

export interface AdapterAdmitOptions {
	/** `false` turns rate limiting off (for example when a gateway already does it). */
	rateLimit?: false | AdapterRateLimitOptions;
	/** Origins allowed to send cookie-authenticated writes, e.g. `["https://app.example.com"]`. The request's own origin is always allowed. Set this when a proxy rewrites the `Host` header. */
	trustedOrigins?: string[];
	/** `false` turns the cross-site check off. */
	csrf?: boolean;
	/** Receives the warning that rate limiting fails open when the counter store errors, and the one-time warning on the first request whose client IP is unknown. */
	logger?: Pick<TheAuthLogger, "warn">;
}

export interface AdapterAdmission {
	/** A 429 or 403 Response to send, or null when the request may proceed. */
	admit(request: Request, relativePath: string): Promise<Response | null>;
}

const STRICT_PATHS = ["/mcp/token", "/mcp/register", "/mcp/authorize", "/authorize"];
const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

function json(status: number, code: string, message: string, headers?: HeadersInit): Response {
	return new Response(JSON.stringify({ error: { code, message } }), {
		status,
		headers: { "Content-Type": "application/json", ...headers },
	});
}

function tierOf(method: string, path: string): Tier {
	const p = path.split("?")[0]?.toLowerCase() ?? "";
	// `endsWith` covers adapters that pass the full path including the mount prefix.
	if (STRICT_PATHS.some((s) => p === s || p.startsWith(`${s}/`) || p.endsWith(s))) return "strict";
	return SAFE_METHODS.has(method) ? "read" : "mutation";
}

/**
 * Bucket for a client whose IP is unknown. Low cardinality on purpose: only the KIND of credential is
 * used, never its value, so a random Cookie or Authorization header cannot mint a new bucket per request.
 * Per-client limits need a trusted proxy setting or a `key` function (see `rateLimit.key`).
 */
function bucketKey(
	request: Request,
	proxy: TrustedProxyConfig | undefined,
	onUnknown: () => void,
): string {
	const ip = resolveRequestIp(request, proxy);
	if (ip) return `ip:${ip}`;
	onUnknown();
	if (request.headers.get("authorization")) return "unknown:authorization";
	if (request.headers.get("cookie")) return "unknown:cookie";
	return "unknown:anonymous";
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

const DEFAULT_LIMITS: Record<Tier, RateLimitConfig> = {
	strict: { max: 30, window: 60 },
	mutation: { max: 120, window: 60 },
	read: { max: 300, window: 60 },
};

type Tier = "strict" | "mutation" | "read";

/** are then enforced across instances. Without it each process counts alone. A store failure lets the request through by default, so an outage there never takes authentication down with it. Set `rateLimit.failClosed` to refuse with a 503 instead. */
export function createAdapterAdmission(
	options: AdapterAdmitOptions | undefined,
	proxy: TrustedProxyConfig | undefined,
	store?: SecondaryStorage,
): AdapterAdmission {
	const limits = options?.rateLimit === false ? null : (options?.rateLimit ?? {});
	const configured: Record<Tier, RateLimitConfig> = {
		strict: limits?.strict ?? DEFAULT_LIMITS.strict,
		mutation: limits?.mutation ?? DEFAULT_LIMITS.mutation,
		read: limits?.read ?? DEFAULT_LIMITS.read,
	};
	const limiters: Record<Tier, RateLimiter> | null =
		limits && !store
			? {
					strict: createRateLimiter(configured.strict),
					mutation: createRateLimiter(configured.mutation),
					read: createRateLimiter(configured.read),
				}
			: null;

	const failClosed = limits?.failClosed === true;
	if (limits && store && !failClosed) {
		options?.logger?.warn(
			"adapter rate limiting fails open: when the counter store errors, requests (sign-in and sign-up included) are admitted unthrottled. Set rateLimit.failClosed to refuse them instead.",
			{ failClosed: false },
		);
	}

	let warnedUnknownIp = false;
	const onUnknownIp = (): void => {
		if (warnedUnknownIp) return;
		warnedUnknownIp = true;
		options?.logger?.warn(
			"adapter rate limiting cannot see the client IP: requests share a few fallback buckets (anonymous, cookie, authorization) instead of per-client limits. Set trustedProxy or pass rateLimit.key (a getClientIp style function) for per-client limits.",
			{ source: "adapter-admit", check: "unknown-client-ip" },
		);
	};

	const customKey = limits?.key;
	const skip = limits?.skip;

	const tooMany = (retrySeconds: number): Response =>
		json(429, "RATE_LIMITED", "Too many requests", {
			"Retry-After": String(Math.max(1, Math.ceil(retrySeconds))),
		});

	async function overLimit(tier: Tier, key: string): Promise<Response | null> {
		if (!limits) return null;
		if (store) {
			try {
				const { max, window } = configured[tier];
				const hit = await store.incr(`adapter:${tier}:${key}`, window);
				return hit.count > max ? tooMany((hit.expiresAt - Date.now()) / 1000) : null;
			} catch {
				return failClosed
					? json(503, "RATE_LIMIT_UNAVAILABLE", "Rate limiting is unavailable", {
							"Retry-After": "5",
						})
					: null;
			}
		}
		const result = limiters?.[tier].check(key);
		if (result && !result.allowed) return tooMany((result.resetAt.getTime() - Date.now()) / 1000);
		return null;
	}
	const trusted = new Set(
		(options?.trustedOrigins ?? []).map(originOf).filter((o): o is string => o !== null),
	);
	const csrf = options?.csrf !== false;

	return {
		async admit(request, relativePath) {
			const tier = tierOf(request.method.toUpperCase(), relativePath);
			const skipped = skip?.(request, relativePath) === true;
			const key = customKey?.(request) ?? bucketKey(request, proxy, onUnknownIp);
			const limited = skipped ? null : await overLimit(tier, key);
			if (limited) return limited;
			return csrf ? crossSiteDenial(request, trusted) : null;
		},
	};
}

/** The slice of an Express-style response `writeRefusal` needs. */
export interface RefusalTarget {
	status(code: number): unknown;
	setHeader(name: string, value: string): unknown;
	send(body: string): unknown;
}

/** Write a Response returned by `admit` onto an Express-style response. */
export async function writeRefusal(refused: Response, res: RefusalTarget): Promise<void> {
	for (const [name, value] of refused.headers) res.setHeader(name, value);
	const body = await refused.text();
	res.status(refused.status);
	res.send(body);
}
