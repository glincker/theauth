/**
 * rateLimit() plugin: per-endpoint, per-IP or per-client rate limits for auth endpoints.
 *
 * @example
 * ```typescript
 * import { createTheAuth } from '@glinr/theauth';
 * import { rateLimit } from '@glinr/theauth/auth';
 * import { kvStore } from '@glinr/theauth/auth/stores/kv';
 *
 * const theauth = createTheAuth({
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

import type { TheAuthLogger } from "../observability/types.js";
import type { TheAuthPlugin } from "../plugin/types.js";
import { isSecondaryStorage, rateLimitStoreFromStorage } from "../storage/rate-limit-store.js";
import type { SecondaryStorage } from "../storage/types.js";
import type { TrustedProxyConfig } from "./client-ip.js";
import { resolveClientIp } from "./client-ip.js";
import { MemoryStore } from "./stores/memory.js";
import type { RateLimitStore } from "./stores/types.js";

export type { RateLimitStore };

export interface EndpointLimit {
	/** Duration string: "15m", "1h", "30s", "1d" */
	window: string;
	max: number;
}

/** What identifies a caller for rate limiting. */
export type RateLimitKeyBy = "ip" | "client_id" | "ip+client_id";

export interface RateLimitConfig extends TrustedProxyConfig {
	signIn?: EndpointLimit;
	signUp?: EndpointLimit;
	passwordReset?: EndpointLimit;
	agentAuthorize?: EndpointLimit;
	/** Limit for POST /mcp/token. Default 60 per minute. `false` disables. */
	mcpToken?: EndpointLimit | false;
	/** Limit for POST /mcp/register (dynamic client registration). Default 10 per hour. `false` disables. */
	mcpRegister?: EndpointLimit | false;
	/** Limit for POST /auth/device/code. Default 10 per minute. `false` disables. */
	deviceCode?: EndpointLimit | false;
	/** Limit for POST /auth/device/token (polling). Default 60 per minute. `false` disables. */
	deviceToken?: EndpointLimit | false;
	/** Limit for POST /auth/device/authorize. Default 20 per minute. `false` disables. */
	deviceAuthorize?: EndpointLimit | false;
	/** Fallback limit applied to all other /auth/* paths */
	default?: EndpointLimit;
	/** What to key counters on: `ip`, `client_id`, or `ip+client_id`. */
	keyBy?: RateLimitKeyBy;
	/** Storage backend. Pass `"memory"` (or omit) for the built-in store, or any RateLimitStore or SecondaryStorage. */
	store?: "memory" | RateLimitStore | SecondaryStorage;
	/** Extracts the client part of the rate-limit key from the request. Defaults to the IP from `trustedProxy`. */
	keyExtractor?: (request: Request) => string;
	/** What to do when the counter store errors. `false` (default) lets the request through, so a store outage never takes sign-in down. `true` refuses it with a 503. */
	failClosed?: boolean;
	/** Receives store errors and the startup warning that the limiter fails open. */
	logger?: Pick<TheAuthLogger, "warn">;
	/** Custom response when a limit is exceeded. Defaults to a JSON 429 response. */
	onLimit?: (request: Request, retryAfter: number) => Response;
}

/** Parse a window string like "15m", "1h", "30s", "1d" into milliseconds */
function parseWindowMs(window: string): number {
	const match = /^(\d+)(s|m|h|d)$/.exec(window);
	if (!match) {
		throw new Error(
			`Invalid rate limit window "${window}". Expected format: <number><s|m|h|d> e.g. "15m", "1h".`,
		);
	}
	const value = parseInt(match[1] ?? "0", 10);
	if (value <= 0) {
		throw new Error(`Invalid rate limit window "${window}". The duration must be above 0.`);
	}
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

const MAX_BODY_SCAN_BYTES = 8_192;

/** Stream-read at most `limit` bytes of the body, then cancel the rest. */
async function readBodyPrefix(request: Request, limit: number): Promise<string> {
	const body = request.body;
	if (!body) return "";
	const reader = body.getReader();
	const chunks: Uint8Array[] = [];
	let total = 0;
	try {
		while (total < limit) {
			const { done, value } = await reader.read();
			if (done) break;
			const take = value.byteLength > limit - total ? value.subarray(0, limit - total) : value;
			chunks.push(take);
			total += take.byteLength;
		}
	} finally {
		// Not awaited: on a cloned (tee'd) body the cancel promise settles only
		// once the other branch is cancelled too, which is the handler's to read.
		reader.cancel().catch(() => undefined);
	}
	const merged = new Uint8Array(total);
	let offset = 0;
	for (const chunk of chunks) {
		merged.set(chunk, offset);
		offset += chunk.byteLength;
	}
	return new TextDecoder().decode(merged);
}

/** Read an OAuth client_id from the query, Basic auth, or a small form/JSON body. */
async function extractClientId(request: Request): Promise<string | null> {
	const url = new URL(request.url);
	const fromQuery = url.searchParams.get("client_id");
	if (fromQuery) return fromQuery.slice(0, 128);

	const auth = request.headers.get("authorization");
	if (auth?.toLowerCase().startsWith("basic ")) {
		try {
			const decoded = atob(auth.slice(6).trim());
			const user = decoded.split(":")[0];
			if (user) return decodeURIComponent(user).slice(0, 128);
		} catch {}
	}

	if (request.method !== "POST") return null;
	const type = request.headers.get("content-type") ?? "";
	const isForm = type.includes("application/x-www-form-urlencoded");
	const isJson = type.includes("application/json");
	if (!isForm && !isJson) return null;
	try {
		const text = await readBodyPrefix(request.clone(), MAX_BODY_SCAN_BYTES);
		if (isForm) return new URLSearchParams(text).get("client_id")?.slice(0, 128) ?? null;
		const parsed: unknown = JSON.parse(text);
		if (parsed && typeof parsed === "object") {
			const id = (parsed as Record<string, unknown>).client_id;
			if (typeof id === "string" && id) return id.slice(0, 128);
		}
	} catch {}
	return null;
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

type EndpointKey =
	| "signIn"
	| "signUp"
	| "passwordReset"
	| "agentAuthorize"
	| "mcpToken"
	| "mcpRegister"
	| "deviceCode"
	| "deviceToken"
	| "deviceAuthorize";

const PATH_TO_CONFIG_KEY: Array<[string, EndpointKey]> = [
	["/auth/sign-in", "signIn"],
	["/auth/sign-up", "signUp"],
	["/auth/password-reset", "passwordReset"],
	["/auth/agent/authorize", "agentAuthorize"],
	["/auth/device/code", "deviceCode"],
	["/auth/device/token", "deviceToken"],
	["/auth/device/authorize", "deviceAuthorize"],
	["/mcp/token", "mcpToken"],
	["/mcp/register", "mcpRegister"],
];

/** Applied when the caller does not configure the endpoint. */
const BUILT_IN_LIMITS: Partial<Record<EndpointKey, EndpointLimit>> = {
	mcpToken: { window: "1m", max: 60 },
	mcpRegister: { window: "1h", max: 10 },
	deviceCode: { window: "1m", max: 10 },
	deviceToken: { window: "1m", max: 60 },
	deviceAuthorize: { window: "1m", max: 20 },
};

function resolveLimit(pathname: string, config: RateLimitConfig): EndpointLimit | undefined {
	for (const [suffix, key] of PATH_TO_CONFIG_KEY) {
		if (pathname === suffix || pathname.endsWith(suffix)) {
			const configured = config[key];
			if (configured === false) return undefined;
			return configured ?? BUILT_IN_LIMITS[key] ?? config.default;
		}
	}
	return pathname.includes("/auth/") ? config.default : undefined;
}

export function rateLimit(config: RateLimitConfig = {}): TheAuthPlugin {
	// Parse every configured window once, so a bad value fails at startup and
	// requests do not re-parse.
	const windowMsCache = new Map<string, number>();
	const windowMsFor = (window: string): number => {
		let ms = windowMsCache.get(window);
		if (ms === undefined) {
			ms = parseWindowMs(window);
			windowMsCache.set(window, ms);
		}
		return ms;
	};
	const configured: Array<EndpointLimit | false | undefined> = [
		config.default,
		...PATH_TO_CONFIG_KEY.map(([, key]) => config[key]),
		...Object.values(BUILT_IN_LIMITS),
	];
	for (const limit of configured) {
		if (limit) windowMsFor(limit.window);
	}
	let store: RateLimitStore | null = null;
	if (config.store && config.store !== "memory") {
		store = isSecondaryStorage(config.store)
			? rateLimitStoreFromStorage(config.store)
			: (config.store as RateLimitStore);
	}
	const keyBy = config.keyBy ?? "ip";

	const extractIp =
		config.keyExtractor ??
		((request: Request): string => resolveClientIp(request, config) ?? "unknown");
	const onLimitFn = config.onLimit ?? defaultOnLimit;
	const failClosed = config.failClosed === true;
	if (!failClosed) {
		config.logger?.warn(
			"rateLimit plugin fails open: when the counter store errors, requests (sign-in and sign-up included) are let through unthrottled. Set failClosed: true to refuse them instead.",
			{ failClosed: false },
		);
	}

	async function buildKey(request: Request): Promise<string> {
		const ip = extractIp(request);
		if (keyBy === "ip") return ip;
		const clientId = await extractClientId(request);
		if (keyBy === "client_id") return clientId ? `client:${clientId}` : ip;
		return `${ip}|client:${clientId ?? "-"}`;
	}

	function getStore(): RateLimitStore {
		store ??= new MemoryStore();
		return store;
	}

	return {
		id: "theauth-rate-limit",

		async init(ctx): Promise<undefined> {
			// Explicit `store` wins; otherwise follow createTheAuth's secondaryStorage.
			if (!store && ctx.secondaryStorage) {
				store = rateLimitStoreFromStorage(ctx.secondaryStorage.for("rateLimit"));
			}
			return undefined;
		},

		hooks: {
			async onRequest(request: Request): Promise<Request | Response | undefined> {
				const url = new URL(request.url);
				const pathname = url.pathname;

				const limit = resolveLimit(pathname, config);
				if (!limit) {
					return undefined;
				}

				const windowMs = windowMsFor(limit.window);
				const key = `rate-limit:${pathname}:${await buildKey(request)}`;

				let hit: { count: number; resetAt: number };
				try {
					hit = await getStore().increment(key, windowMs);
				} catch (err) {
					config.logger?.warn("rateLimit store error", {
						failClosed,
						error: err instanceof Error ? err.message : String(err),
					});
					if (!failClosed) return undefined;
					return new Response(
						JSON.stringify({
							error: { code: "RATE_LIMIT_UNAVAILABLE", message: "Rate limiting is unavailable" },
						}),
						{ status: 503, headers: { "Content-Type": "application/json", "Retry-After": "5" } },
					);
				}
				const { count, resetAt } = hit;

				if (count > limit.max) {
					const retryAfterMs = Math.max(resetAt - Date.now(), 0);
					const retryAfterSeconds = Math.ceil(retryAfterMs / 1000);
					const response = onLimitFn(request, Math.max(retryAfterSeconds, 1));

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

				// Under the limit: let the request through. Headers can only be attached to the response.
				return undefined;
			},
		},
	};
}
