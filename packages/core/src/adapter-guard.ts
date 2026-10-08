/**
 * Shared authentication guard for the framework adapters (hono, express,
 * fastify, nestjs, nextjs, nuxt, sveltekit, astro, solidstart, tanstack).
 *
 * The adapters expose agent, delegation, audit and dashboard management
 * routes. Those must never be reachable anonymously, so every adapter builds
 * a guard with `createAdapterGuard` and fails closed when nothing can
 * authenticate a caller.
 */

import { extractToken } from "./plugin/helpers.js";
import type { TheAuth } from "./theauth.js";

/** The caller identified by an {@link AdapterAuthResolver}. */
export interface AdapterPrincipal {
	/** Stable identifier of the caller (user id, service id, ...). */
	id: string;
	/** Free-form data the resolver wants to keep (roles, scopes, ...). */
	[key: string]: unknown;
}

/**
 * Decide who is calling. Return a principal to allow the request or `null`
 * to reject it with 401. Throwing is treated as a rejection.
 */
export type AdapterAuthResolver = (request: Request) => Promise<AdapterPrincipal | null>;

/** Security options shared by every adapter. */
export interface AdapterSecurityOptions {
	/**
	 * Resolver for the management routes (`/agents`, `/delegations`, `/audit`,
	 * `/dashboard`, `/authorize`). When omitted, the guard accepts a valid
	 * session (cookie or `Authorization: Bearer <session token>`) and requires
	 * `auth.session` to be configured on the TheAuth instance.
	 *
	 * The default accepts any signed-in user. Pass your own resolver to limit
	 * these routes to admins or service tokens.
	 */
	authenticate?: AdapterAuthResolver;
	/**
	 * Serve the management routes without authentication. Local development
	 * only: a warning is logged on startup. Never enable this in production.
	 */
	allowUnauthenticated?: boolean;
}

export interface AdapterGuard {
	/** True when `relativePath` (relative to the adapter mount) needs a caller. */
	isProtected(relativePath: string): boolean;
	/** Returns a 401 Response to send, or null when the request may proceed. */
	check(request: Request): Promise<Response | null>;
}

const PROTECTED_PREFIXES = ["/agents", "/delegations", "/audit", "/dashboard"];

/**
 * Normalise a path for matching: strip query, decode, lowercase (some
 * frameworks route case-insensitively), collapse duplicate slashes and drop
 * the trailing slash.
 */
function normalisePath(path: string): string {
	const noQuery = path.split("?")[0] ?? "";
	let decoded = noQuery;
	try {
		decoded = decodeURIComponent(noQuery);
	} catch {
		// keep the raw value; it will not match a route either
	}
	const collapsed = `/${decoded.toLowerCase()}`.replace(/\/{2,}/g, "/");
	return collapsed.length > 1 && collapsed.endsWith("/") ? collapsed.slice(0, -1) : collapsed;
}

/** Whether a path (relative to the adapter mount) is a protected management route. */
export function isProtectedAdapterPath(relativePath: string): boolean {
	const p = normalisePath(relativePath);
	if (p === "/authorize") return true;
	return PROTECTED_PREFIXES.some((prefix) => p === prefix || p.startsWith(`${prefix}/`));
}

function jsonUnauthorized(): Response {
	return new Response(
		JSON.stringify({ error: { code: "UNAUTHORIZED", message: "Authentication required" } }),
		{
			status: 401,
			headers: { "Content-Type": "application/json", "WWW-Authenticate": "Bearer" },
		},
	);
}

function sessionResolver(theauth: TheAuth): AdapterAuthResolver | null {
	const sessions = theauth.auth.session;
	if (!sessions) return null;
	return async (request) => {
		const viaAdapter = await theauth.auth.resolveUser(request);
		if (viaAdapter) return { id: viaAdapter.id };
		const token = extractToken(request);
		if (!token) return null;
		const session = await sessions.validate(token);
		return session ? { id: session.userId } : null;
	};
}

/**
 * Build the guard for one adapter instance. Throws at construction when no
 * authentication is configured and `allowUnauthenticated` is not set, so a
 * misconfigured server refuses to start instead of serving open routes.
 */
export function createAdapterGuard(
	theauth: TheAuth,
	options: AdapterSecurityOptions | undefined,
	adapterName: string,
): AdapterGuard {
	if (options?.allowUnauthenticated === true) {
		// biome-ignore lint/suspicious/noConsole: deliberate startup warning for an unsafe opt-out
		console.warn(
			`[theauth] ${adapterName}: allowUnauthenticated is enabled. Agent, delegation, audit and dashboard routes are open to anyone. Use this for local development only.`,
		);
		return { isProtected: () => false, check: async () => null };
	}

	const resolver = options?.authenticate ?? sessionResolver(theauth);
	if (!resolver) {
		throw new Error(
			`[theauth] ${adapterName}: the management routes (/agents, /delegations, /audit, /dashboard, /authorize) require authentication, but none is configured. ` +
				"Pass `authenticate: (request) => ...` (return { id } or null), configure `auth.session` on createTheAuth, " +
				"or set `allowUnauthenticated: true` for local development only.",
		);
	}

	return {
		isProtected: isProtectedAdapterPath,
		async check(request) {
			try {
				const principal = await resolver(request);
				return principal ? null : jsonUnauthorized();
			} catch {
				return jsonUnauthorized();
			}
		},
	};
}
