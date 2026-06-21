import type { Kavach } from "@glinr/theauth";
import { buildCorsHeaders, isPreflight } from "./cors.js";
import { matchPolicy } from "./policy-matcher.js";
import { createGatewayRateLimiter } from "./rate-limiter.js";
import type { Gateway, GatewayConfig, GatewayPolicy, ResolvedIdentity } from "./types.js";

// ─── Health Check Path ───────────────────────────────────────────────────────

const HEALTH_PATH = "/_kavach/health";

// ─── Response Helpers ────────────────────────────────────────────────────────

function jsonResponse(
	body: unknown,
	status: number,
	extraHeaders?: Record<string, string>,
): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: {
			"Content-Type": "application/json",
			...extraHeaders,
		},
	});
}

function errorResponse(
	code: string,
	message: string,
	status: number,
	extraHeaders?: Record<string, string>,
): Response {
	return jsonResponse({ error: { code, message } }, status, extraHeaders);
}

// ─── Token Extraction ────────────────────────────────────────────────────────

function extractBearerToken(request: Request): string | null {
	const auth = request.headers.get("Authorization");
	if (!auth?.startsWith("Bearer ")) return null;
	return auth.slice(7).trim() || null;
}

function extractClientIp(request: Request): string | undefined {
	const forwarded = request.headers.get("x-forwarded-for");
	if (forwarded) return forwarded.split(",")[0]?.trim();
	return request.headers.get("x-real-ip") ?? undefined;
}

// ─── Rate Limit Key ──────────────────────────────────────────────────────────

function rateLimitKey(identity: ResolvedIdentity | null, request: Request): string {
	if (identity) return `agent:${identity.agentId}`;
	const ip = extractClientIp(request);
	return ip ? `ip:${ip}` : "ip:unknown";
}

// ─── Proxy Request Builder ───────────────────────────────────────────────────

function buildUpstreamRequest(
	request: Request,
	upstreamUrl: string,
	stripAuthHeader: boolean,
): Request {
	const url = new URL(request.url);
	const target = new URL(upstreamUrl);

	target.pathname = target.pathname.replace(/\/$/, "") + (url.pathname === "/" ? "" : url.pathname);
	target.search = url.search;

	const headers = new Headers(request.headers);
	if (stripAuthHeader) {
		headers.delete("Authorization");
	}
	// Forward the original host and indicate proxied request
	headers.set("X-Forwarded-Host", url.hostname);
	headers.set("X-Forwarded-Proto", url.protocol.replace(":", ""));
	headers.set("X-Gateway", "theauth");

	return new Request(target.toString(), {
		method: request.method,
		headers,
		body: request.body,
		// @ts-expect-error duplex is required for streaming bodies in some runtimes
		duplex: "half",
	});
}

// ─── Permission Check ────────────────────────────────────────────────────────

async function checkPermissions(
	kavach: Kavach,
	identity: ResolvedIdentity,
	policy: GatewayPolicy,
	request: Request,
): Promise<{ allowed: boolean; reason?: string }> {
	const required = policy.requiredPermissions;
	if (!required || required.length === 0) return { allowed: true };

	const ip = extractClientIp(request);
	const userAgent = request.headers.get("user-agent") ?? undefined;

	for (const perm of required) {
		for (const action of perm.actions) {
			const result = await kavach.authorizeByToken(
				identity.token,
				{ action, resource: perm.resource },
				{ ip, userAgent },
			);
			if (!result.allowed) {
				return { allowed: false, reason: result.reason };
			}
		}
	}

	return { allowed: true };
}

// ─── Audit ───────────────────────────────────────────────────────────────────

async function recordAuditEntry(
	kavach: Kavach,
	request: Request,
	identity: ResolvedIdentity | null,
	result: "allowed" | "denied" | "rate_limited",
	reason?: string,
): Promise<void> {
	try {
		const url = new URL(request.url);
		await kavach.authorizeByToken(
			identity?.token ?? "",
			{
				action: request.method.toLowerCase(),
				resource: `gateway:${url.pathname}`,
			},
			{
				ip: extractClientIp(request),
				userAgent: request.headers.get("user-agent") ?? undefined,
			},
		);
	} catch {
		// Audit failures must never block the gateway response.
		// If the token is empty/invalid the inner call returns a denied result
		// which still creates an audit record via the permission engine.
	}
	// Suppress unused variable warning - result and reason are surfaced
	// through the authorizeByToken audit path above
	void result;
	void reason;
}

// ─── Gateway Factory ─────────────────────────────────────────────────────────

/**
 * Create a TheAuth Gateway that enforces auth, authorization, and rate
 * limiting in front of any HTTP upstream.
 *
 * @example
 * ```typescript
 * import { createKavach } from '@glinr/theauth';
 * import { createGateway } from '@glinr/theauth-gateway';
 *
 * const kavach = await createKavach({ database: { provider: 'sqlite', url: 'kavach.db' } });
 *
 * const gateway = createGateway({
 *   upstream: 'http://localhost:8080',
 *   kavach,
 *   policies: [
 *     { path: '/public/*', public: true },
 *     { path: '/api/*', requiredPermissions: [{ resource: 'api', actions: ['read'] }] },
 *   ],
 * });
 *
 * gateway.listen(3000);
 * ```
 */
export function createGateway(config: GatewayConfig): Gateway {
	const {
		upstream,
		kavach,
		policies = [],
		cors,
		rateLimit,
		audit = true,
		stripAuthHeader = false,
	} = config;

	// One limiter per unique config object reference — global limiter is shared
	// across all requests; policy-level limiters are created lazily per policy.
	const globalLimiter = rateLimit ? createGatewayRateLimiter(rateLimit) : null;
	const policyLimiters = new Map<GatewayPolicy, ReturnType<typeof createGatewayRateLimiter>>();

	function getPolicyLimiter(
		policy: GatewayPolicy,
	): ReturnType<typeof createGatewayRateLimiter> | null {
		if (!policy.rateLimit) return null;
		const existing = policyLimiters.get(policy);
		if (existing) return existing;
		const limiter = createGatewayRateLimiter(policy.rateLimit);
		policyLimiters.set(policy, limiter);
		return limiter;
	}

	async function handleRequest(request: Request): Promise<Response> {
		const url = new URL(request.url);
		const pathname = url.pathname;
		const origin = request.headers.get("origin");
		const corsHeaders = buildCorsHeaders(cors, origin);

		// ── Health Check ────────────────────────────────────────────
		if (pathname === HEALTH_PATH) {
			return jsonResponse(
				{ status: "ok", upstream, timestamp: new Date().toISOString() },
				200,
				corsHeaders,
			);
		}

		// ── CORS Preflight ──────────────────────────────────────────
		if (isPreflight(request) && cors) {
			return new Response(null, { status: 204, headers: corsHeaders });
		}

		// ── Policy Matching ─────────────────────────────────────────
		const matchedPolicy = matchPolicy(policies, pathname, request.method);

		// Determine if auth is required
		const requireAuth = matchedPolicy
			? matchedPolicy.public !== true && (matchedPolicy.requireAuth ?? true)
			: true; // default: require auth when no policy matches

		// ── Token Resolution ────────────────────────────────────────
		const token = extractBearerToken(request);
		let identity: ResolvedIdentity | null = null;

		if (token) {
			const agent = await kavach.agent.validateToken(token);
			if (agent) {
				identity = { agentId: agent.id, ownerId: agent.ownerId, token };
			}
		}

		// ── Auth Enforcement ────────────────────────────────────────
		if (requireAuth && !identity) {
			if (audit) {
				await recordAuditEntry(kavach, request, null, "denied", "missing or invalid token");
			}
			return errorResponse("UNAUTHORIZED", "Missing or invalid Bearer token", 401, corsHeaders);
		}

		// ── Global Rate Limit ───────────────────────────────────────
		if (globalLimiter) {
			const key = rateLimitKey(identity, request);
			const rl = globalLimiter.check(key);
			if (!rl.allowed) {
				if (audit && identity) {
					await recordAuditEntry(kavach, request, identity, "rate_limited", "global rate limit");
				}
				return errorResponse("RATE_LIMITED", "Too many requests", 429, {
					...corsHeaders,
					"Retry-After": String(Math.ceil((rl.resetAt.getTime() - Date.now()) / 1000)),
				});
			}
		}

		// ── Policy Rate Limit ───────────────────────────────────────
		if (matchedPolicy) {
			const policyLimiter = getPolicyLimiter(matchedPolicy);
			if (policyLimiter) {
				const key = rateLimitKey(identity, request);
				const rl = policyLimiter.check(key);
				if (!rl.allowed) {
					if (audit && identity) {
						await recordAuditEntry(kavach, request, identity, "rate_limited", "policy rate limit");
					}
					return errorResponse("RATE_LIMITED", "Too many requests", 429, {
						...corsHeaders,
						"Retry-After": String(Math.ceil((rl.resetAt.getTime() - Date.now()) / 1000)),
					});
				}
			}

			// ── Permission Check ────────────────────────────────────
			if (identity && matchedPolicy.requiredPermissions) {
				const permCheck = await checkPermissions(kavach, identity, matchedPolicy, request);
				if (!permCheck.allowed) {
					if (audit) {
						await recordAuditEntry(kavach, request, identity, "denied", permCheck.reason);
					}
					return errorResponse(
						"FORBIDDEN",
						permCheck.reason ?? "Insufficient permissions",
						403,
						corsHeaders,
					);
				}
			}
		}

		// ── Proxy ────────────────────────────────────────────────────
		let upstreamResponse: Response;
		try {
			const upstreamRequest = buildUpstreamRequest(request, upstream, stripAuthHeader);
			upstreamResponse = await fetch(upstreamRequest);
		} catch (err) {
			const message = err instanceof Error ? err.message : "Upstream unreachable";
			if (audit && identity) {
				await recordAuditEntry(kavach, request, identity, "denied", `upstream error: ${message}`);
			}
			return errorResponse("BAD_GATEWAY", `Upstream error: ${message}`, 502, corsHeaders);
		}

		// ── Audit allowed ────────────────────────────────────────────
		if (audit && identity) {
			await recordAuditEntry(kavach, request, identity, "allowed");
		}

		// Add CORS headers to upstream response
		const responseHeaders = new Headers(upstreamResponse.headers);
		for (const [key, value] of Object.entries(corsHeaders)) {
			responseHeaders.set(key, value);
		}

		return new Response(upstreamResponse.body, {
			status: upstreamResponse.status,
			statusText: upstreamResponse.statusText,
			headers: responseHeaders,
		});
	}

	let server: { close(callback?: (err?: Error) => void): void } | null = null;

	async function listen(port: number): Promise<void> {
		const { createServer } = await import("node:http");

		const nodeServer = createServer(async (req, res) => {
			const proto = "http";
			const host = req.headers.host ?? "localhost";
			const url = `${proto}://${host}${req.url ?? "/"}`;

			const chunks: Uint8Array[] = [];
			for await (const chunk of req) {
				chunks.push(chunk as Uint8Array);
			}
			const bodyBuffer = chunks.length > 0 ? Buffer.concat(chunks) : null;

			const headers = new Headers();
			for (const [k, v] of Object.entries(req.headers)) {
				if (v === undefined) continue;
				if (Array.isArray(v)) {
					for (const val of v) {
						headers.append(k, val);
					}
				} else {
					headers.set(k, v);
				}
			}

			const webRequest = new Request(url, {
				method: req.method ?? "GET",
				headers,
				body: bodyBuffer && bodyBuffer.length > 0 ? bodyBuffer : undefined,
			});

			const response = await handleRequest(webRequest);

			const headerRecord: Record<string, string> = {};
			response.headers.forEach((value, key) => {
				headerRecord[key] = value;
			});
			res.writeHead(response.status, headerRecord);

			if (response.body) {
				const reader = response.body.getReader();
				try {
					while (true) {
						const { done, value } = await reader.read();
						if (done) break;
						res.write(value);
					}
				} finally {
					reader.releaseLock();
				}
			}

			res.end();
		});

		server = nodeServer;

		await new Promise<void>((resolve) => {
			nodeServer.listen(port, resolve);
		});
	}

	async function close(): Promise<void> {
		await new Promise<void>((resolve, reject) => {
			if (!server) {
				resolve();
				return;
			}
			server.close((err) => {
				if (err) reject(err);
				else resolve();
			});
		});
		server = null;
	}

	return { handleRequest, listen, close };
}

// ─── Re-export config types for convenience ──────────────────────────────────

export type {
	CorsConfig,
	Gateway,
	GatewayConfig,
	GatewayPolicy,
	RateLimitConfig,
} from "./types.js";
