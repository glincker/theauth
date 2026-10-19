import type { InputSource, TheAuth, TrustedProxyConfig } from "@glinr/theauth";
import { INPUTS_HEADER, parseInputsHeader, resolveClientIp } from "@glinr/theauth";
import { buildCorsHeaders, isOriginAllowed, isPreflight } from "./cors.js";
import { authenticateMcp, metadataResponse, resolveMcp } from "./mcp-mode.js";
import { startServer } from "./node-server.js";
import { matchPolicy } from "./policy-matcher.js";
import type { BodyLimit } from "./proxy.js";
import {
	buildClientResponse,
	buildUpstreamRequest,
	DEFAULT_MAX_BODY_BYTES,
	DEFAULT_UPSTREAM_TIMEOUT_MS,
	fetchUpstream,
	limitBody,
	parseUpstream,
} from "./proxy.js";
import { createGatewayRateLimiter } from "./rate-limiter.js";
import type { Gateway, GatewayConfig, GatewayPolicy, ResolvedIdentity } from "./types.js";

const HEALTH_PATH = "/_theauth/health";

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

function extractBearerToken(request: Request): string | null {
	const auth = request.headers.get("Authorization");
	if (!auth?.startsWith("Bearer ")) return null;
	return auth.slice(7).trim() || null;
}

/**
 * Resolve the client IP through the trusted proxy helper. With no
 * `trustedProxy` config the result is undefined: forwarded headers are
 * client controlled and are ignored. Callers must fail closed on undefined.
 */
function extractClientIp(request: Request, trustedProxy?: TrustedProxyConfig): string | undefined {
	return resolveClientIp(request, trustedProxy) ?? undefined;
}

/** Small non-cryptographic hash that keeps limiter keys bounded in size. */
function fingerprint(value: string): string {
	let h = 0x811c9dc5;
	for (let i = 0; i < value.length; i++) {
		h ^= value.charCodeAt(i);
		h = Math.imul(h, 0x01000193);
	}
	return (h >>> 0).toString(36);
}

/**
 * Key for the rate limiter. Authenticated callers are keyed by agent. Others
 * are keyed by the trusted client IP when one is configured. When the IP is
 * unknown the key is a fingerprint of the presented token and ordinary client
 * headers, never one constant bucket: a single shared key would let one
 * client exhaust the budget of every unauthenticated caller. The fingerprint
 * is best effort (a client can vary its headers); configure `trustedProxy`
 * for strict per-IP limiting.
 */
function rateLimitKey(
	identity: ResolvedIdentity | null,
	request: Request,
	trustedProxy?: TrustedProxyConfig,
): string {
	if (identity) return `agent:${identity.agentId}`;
	const ip = extractClientIp(request, trustedProxy);
	if (ip) return `ip:${ip}`;
	const h = request.headers;
	const material = [
		h.get("authorization") ?? "",
		h.get("user-agent") ?? "",
		h.get("accept-language") ?? "",
		h.get("accept-encoding") ?? "",
	].join("\n");
	return `anon:${fingerprint(material)}`;
}

/**
 * Context for the permission and audit calls. `TheAuth-Inputs` carries the caller's claim of what was in context for this request (kind and hash per input, see provenance-wire in core). A malformed header is ignored, it never blocks the request.
 */
function callContext(
	request: Request,
	trustedProxy?: TrustedProxyConfig,
): { ip?: string; userAgent?: string; inputs?: InputSource[] } {
	const inputs = parseInputsHeader(request.headers.get(INPUTS_HEADER));
	return {
		ip: extractClientIp(request, trustedProxy),
		userAgent: request.headers.get("user-agent") ?? undefined,
		...(inputs ? { inputs } : {}),
	};
}

async function authorizeIdentity(
	theauth: TheAuth,
	identity: ResolvedIdentity,
	action: string,
	resource: string,
	context: { ip?: string; userAgent?: string; inputs?: InputSource[] },
): Promise<{ allowed: boolean; reason?: string }> {
	if (identity.kind === "agent-token") {
		return theauth.authorizeByToken(identity.token, { action, resource }, context);
	}
	// OAuth callers are checked as the agent named in the token. A token with no
	// agent claim has no permissions to evaluate, so a permission policy fails closed.
	if (!identity.mcpAgentId) {
		return { allowed: false, reason: "Token carries no agent identity for permission checks" };
	}
	return theauth.authorize(identity.mcpAgentId, { action, resource, context });
}

async function checkPermissions(
	theauth: TheAuth,
	identity: ResolvedIdentity,
	policy: GatewayPolicy,
	request: Request,
	trustedProxy?: TrustedProxyConfig,
): Promise<{ allowed: boolean; reason?: string }> {
	const required = policy.requiredPermissions;
	if (!required || required.length === 0) return { allowed: true };

	const context = callContext(request, trustedProxy);

	for (const perm of required) {
		for (const action of perm.actions) {
			const result = await authorizeIdentity(theauth, identity, action, perm.resource, context);
			if (!result.allowed) {
				return { allowed: false, reason: result.reason };
			}
		}
	}

	return { allowed: true };
}

async function recordAuditEntry(
	theauth: TheAuth,
	request: Request,
	identity: ResolvedIdentity | null,
	trustedProxy?: TrustedProxyConfig,
): Promise<void> {
	const url = new URL(request.url);
	const action = request.method.toLowerCase();
	const resource = `gateway:${url.pathname}`;
	const context = callContext(request, trustedProxy);
	try {
		if (!identity) {
			await theauth.authorizeByToken("", { action, resource }, context);
		} else if (identity.kind === "agent-token" || identity.mcpAgentId) {
			await authorizeIdentity(theauth, identity, action, resource, context);
		}
	} catch {
		// Audit failures must never block the gateway response.
	}
}

/**
 * Create a TheAuth Gateway that enforces auth, authorization, and rate
 * limiting in front of any HTTP upstream.
 *
 * @example
 * ```typescript
 * import { createTheAuth } from '@glinr/theauth';
 * import { createGateway } from '@glinr/theauth-gateway';
 *
 * const theauth = await createTheAuth({ database: { provider: 'sqlite-native', url: 'theauth.db' } });
 *
 * const gateway = createGateway({
 *   upstream: 'http://localhost:8080',
 *   theauth,
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
		theauth,
		policies = [],
		cors,
		rateLimit,
		audit = true,
		stripAuthHeader = true,
		trustedProxy,
		maxBodyBytes = DEFAULT_MAX_BODY_BYTES,
		upstreamTimeoutMs = DEFAULT_UPSTREAM_TIMEOUT_MS,
	} = config;

	// Fail at startup, not on the first request.
	const upstreamUrl = parseUpstream(upstream);
	const mcp = config.mcp ? resolveMcp(config.mcp) : null;
	if (!mcp && policies.some((p) => p.requiredScopes && p.requiredScopes.length > 0)) {
		throw new Error(
			"Policies with requiredScopes need the mcp option (scopes come from OAuth tokens)",
		);
	}

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

	function rateLimited(resetAt: Date, corsHeaders: Record<string, string>): Response {
		return errorResponse("RATE_LIMITED", "Too many requests", 429, {
			...corsHeaders,
			"Retry-After": String(Math.max(1, Math.ceil((resetAt.getTime() - Date.now()) / 1000))),
		});
	}

	async function handleRequest(request: Request): Promise<Response> {
		const url = new URL(request.url);
		const pathname = url.pathname;
		const origin = request.headers.get("origin");
		const corsHeaders = buildCorsHeaders(cors, origin, mcp !== null);

		// Health Check (never reveals where the upstream lives)
		if (pathname === HEALTH_PATH) {
			return jsonResponse(
				{ status: "ok", mode: mcp ? "mcp" : "agent-token", timestamp: new Date().toISOString() },
				200,
				corsHeaders,
			);
		}

		// RFC 9728 protected resource metadata for the upstream
		if (
			mcp &&
			(request.method === "GET" || request.method === "HEAD") &&
			mcp.metadataPaths.includes(pathname)
		) {
			return metadataResponse(mcp, corsHeaders);
		}

		// Browsers can be steered at a local MCP server by a hostile page
		// (DNS rebinding). The MCP spec requires Origin validation.
		if (mcp && !isOriginAllowed(cors, origin, url.host)) {
			return errorResponse("FORBIDDEN", "Origin not allowed", 403, corsHeaders);
		}

		if (isPreflight(request) && cors) {
			return new Response(null, { status: 204, headers: corsHeaders });
		}

		const matchedPolicy = matchPolicy(policies, pathname, request.method);
		const requireAuth = matchedPolicy
			? matchedPolicy.public !== true && (matchedPolicy.requireAuth ?? true)
			: true;

		let identity: ResolvedIdentity | null = null;
		if (mcp && requireAuth) {
			const result = await authenticateMcp(mcp, request, matchedPolicy?.requiredScopes);
			if (!result.ok) {
				const failed = new Response(result.response.body, result.response);
				for (const [k, v] of Object.entries(corsHeaders)) failed.headers.set(k, v);
				return failed;
			}
			const p = result.principal;
			identity = {
				agentId: p.agent?.id ?? `oauth:${p.clientId}:${p.userId}`,
				ownerId: p.userId,
				token: "",
				kind: "mcp",
				mcpAgentId: p.agent?.id,
			};
		} else if (!mcp) {
			const token = extractBearerToken(request);
			if (token) {
				const agent = await theauth.agent.validateToken(token);
				if (agent) {
					identity = { agentId: agent.id, ownerId: agent.ownerId, token, kind: "agent-token" };
				}
			}
			if (requireAuth && !identity) {
				if (audit) await recordAuditEntry(theauth, request, null, trustedProxy);
				return errorResponse("UNAUTHORIZED", "Missing or invalid Bearer token", 401, {
					...corsHeaders,
					"WWW-Authenticate": 'Bearer realm="theauth-gateway"',
				});
			}
		}

		if (globalLimiter) {
			const rl = globalLimiter.check(rateLimitKey(identity, request, trustedProxy));
			if (!rl.allowed) {
				if (audit && identity) await recordAuditEntry(theauth, request, identity, trustedProxy);
				return rateLimited(rl.resetAt, corsHeaders);
			}
		}

		if (matchedPolicy) {
			const policyLimiter = getPolicyLimiter(matchedPolicy);
			if (policyLimiter) {
				const rl = policyLimiter.check(rateLimitKey(identity, request, trustedProxy));
				if (!rl.allowed) {
					if (audit && identity) await recordAuditEntry(theauth, request, identity, trustedProxy);
					return rateLimited(rl.resetAt, corsHeaders);
				}
			}

			if (identity && matchedPolicy.requiredPermissions) {
				const permCheck = await checkPermissions(
					theauth,
					identity,
					matchedPolicy,
					request,
					trustedProxy,
				);
				if (!permCheck.allowed) {
					if (audit) await recordAuditEntry(theauth, request, identity, trustedProxy);
					return errorResponse(
						"FORBIDDEN",
						permCheck.reason ?? "Insufficient permissions",
						403,
						corsHeaders,
					);
				}
			}
		}

		const limit: BodyLimit = { max: maxBodyBytes, exceeded: false };
		const limited = limitBody(request, limit);
		if (limited.tooLarge) {
			return errorResponse("PAYLOAD_TOO_LARGE", "Request body too large", 413, corsHeaders);
		}
		const clientIp = extractClientIp(request, trustedProxy);

		let upstreamResponse: Response;
		try {
			const outcome = await fetchUpstream(
				(signal) =>
					buildUpstreamRequest(request, upstreamUrl, {
						stripAuthHeader,
						clientIp,
						signal,
						body: limited.body,
					}),
				request.signal,
				upstreamTimeoutMs,
			);
			if (outcome.timedOut) {
				return errorResponse(
					"GATEWAY_TIMEOUT",
					"The upstream did not respond in time",
					504,
					corsHeaders,
				);
			}
			upstreamResponse = outcome.response;
		} catch {
			if (limit.exceeded) {
				return errorResponse("PAYLOAD_TOO_LARGE", "Request body too large", 413, corsHeaders);
			}
			// The cause stays out of the response: it can name internal hosts and ports.
			return errorResponse("BAD_GATEWAY", "The upstream is unreachable", 502, corsHeaders);
		}

		if (audit && identity) await recordAuditEntry(theauth, request, identity, trustedProxy);

		return buildClientResponse(upstreamResponse, upstreamUrl, url.origin, corsHeaders);
	}

	let server: { close(callback?: (err?: Error) => void): void } | null = null;

	async function listen(port: number): Promise<void> {
		server = await startServer(handleRequest, port);
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

export type {
	CorsConfig,
	Gateway,
	GatewayConfig,
	GatewayMcpConfig,
	GatewayPolicy,
	RateLimitConfig,
} from "./types.js";
