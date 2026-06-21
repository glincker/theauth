/**
 * Edge-runtime safe middleware factory.
 * NO `server-only` import — this file must work in the Edge runtime.
 * NO `next/headers` import — cookies are read from NextRequest directly.
 */

import type { NextRequest, NextResponse as NextResponseType } from "next/server";
import { NextResponse } from "next/server";
import { generateCsrfToken } from "./csrf.js";
import { isTokenExpiring } from "./jwt.js";
import type { ResolvedAuthConfig } from "./types.js";

// createAuthConfig is a pure function — safe to use in Edge runtime.
export { createAuthConfig } from "./config.js";
export { readJwtExp } from "./jwt.js";
export type { AuthConfig, AuthSession, DefaultUser, ResolvedAuthConfig } from "./types.js";

interface MiddlewareOptions {
	/**
	 * Paths that require authentication. On these paths, if the session cannot
	 * be established after a refresh attempt, the user is redirected to signInPath.
	 * Supports simple prefix matching: "/app" matches "/app", "/app/dashboard", etc.
	 */
	protectedPaths?: string[];
	/**
	 * Path to redirect to when authentication is required. Default: "/signin".
	 * The original path is appended as `?next=<path>`.
	 */
	signInPath?: string;
	/**
	 * Maximum milliseconds to wait for a refresh request before letting the
	 * request through unauthenticated. Default: 4000.
	 */
	refreshTimeoutMs?: number;
}

interface RefreshTokenResponse {
	accessToken?: string;
	refreshToken?: string;
}

/**
 * Middleware factory. Wraps a Next.js middleware with:
 * 1. x-pathname header forwarding (for layouts to build ?next= redirects).
 * 2. Proactive JWT refresh when the access token is missing or expiring.
 * 3. Protected-path redirect to signInPath when auth cannot be established.
 *
 * @example
 * ```ts
 * // middleware.ts (project root)
 * import { withAuth } from "@glinr/theauth-nextjs-auth/middleware";
 * import { authConfig } from "@/lib/auth/config";
 *
 * export default withAuth(authConfig, {
 *   protectedPaths: ["/app"],
 *   signInPath: "/signin",
 * });
 *
 * export const config = { matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"] };
 * ```
 */
export function withAuth<TUser>(
	config: ResolvedAuthConfig<TUser>,
	options: MiddlewareOptions = {},
): (req: NextRequest) => Promise<NextResponseType> {
	const { protectedPaths = [], signInPath = "/signin", refreshTimeoutMs = 4000 } = options;

	return async function authMiddleware(req: NextRequest): Promise<NextResponseType> {
		const pathname = req.nextUrl.pathname;

		// Forward pathname so RSCs can construct next= redirect URLs.
		const reqHeaders = new Headers(req.headers);
		reqHeaders.set("x-pathname", pathname);

		const response = NextResponse.next({ request: { headers: reqHeaders } });

		// Read access token from request cookies (both __Host- and plain variants).
		const { sessionPrefix } = config.cookies;
		const accessToken =
			req.cookies.get(`__Host-${sessionPrefix}-token`)?.value ??
			req.cookies.get(`${sessionPrefix}-token`)?.value;
		const refreshToken = req.cookies.get(config.cookies.refresh)?.value;

		const needsRefresh = !accessToken || isTokenExpiring(accessToken, config.expiryRefreshBufferS);

		// Start optimistically: any existing token (even an expiring one) counts as valid
		// until we confirm otherwise. This prevents bouncing users to /signin on transient
		// refresh failures (network blips, backend hiccups) when their token is still
		// accepted by the backend for the expiryRefreshBufferS grace window.
		let hasValidSession = Boolean(accessToken);

		if (needsRefresh && refreshToken) {
			const refreshed = await _tryRefresh(config, refreshToken, refreshTimeoutMs);
			if (refreshed) {
				hasValidSession = true;
				_writeSessionCookies(response, refreshed, config);
			} else if (!accessToken) {
				// No existing token at all AND refresh failed → definitely unauthenticated.
				hasValidSession = false;
			}
			// If we had a (possibly expiring) token and refresh failed, keep
			// hasValidSession=true and let the backend validate it downstream.
		}

		// Redirect unauthenticated users away from protected paths.
		if (protectedPaths.length > 0 && !hasValidSession) {
			const isProtected = protectedPaths.some(
				(p) => pathname === p || pathname.startsWith(`${p}/`),
			);
			if (isProtected) {
				const signInUrl = req.nextUrl.clone();
				signInUrl.pathname = signInPath;
				signInUrl.searchParams.set("next", pathname);
				return NextResponse.redirect(signInUrl, { status: 307 });
			}
		}

		return response;
	};
}

async function _tryRefresh<TUser>(
	config: ResolvedAuthConfig<TUser>,
	refreshToken: string,
	timeoutMs: number,
): Promise<{ accessToken: string; refreshToken?: string; csrfToken: string } | null> {
	const controller = new AbortController();
	const timer = setTimeout(() => controller.abort(), timeoutMs);

	try {
		const res = await fetch(`${config.backendUrl}${config.endpoints.refresh}`, {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				Accept: "application/json",
				Origin: config.appUrl,
				"X-Client-Origin": config.appUrl,
				...(config.tenantDomain ? { "X-Tenant-Domain": config.tenantDomain } : {}),
			},
			body: JSON.stringify({ refreshToken }),
			signal: controller.signal,
		});

		clearTimeout(timer);
		if (!res.ok) return null;

		const data = (await res.json()) as RefreshTokenResponse;
		if (!data.accessToken) return null;

		return {
			accessToken: data.accessToken,
			refreshToken: data.refreshToken,
			csrfToken: generateCsrfToken(),
		};
	} catch {
		clearTimeout(timer);
		return null;
	}
}

function _writeSessionCookies<TUser>(
	response: NextResponseType,
	tokens: { accessToken: string; refreshToken?: string; csrfToken: string },
	config: ResolvedAuthConfig<TUser>,
): void {
	const sessionOpts = {
		httpOnly: true,
		secure: config.isProd,
		sameSite: "lax" as const,
		path: "/",
		maxAge: 60 * 60 * 24 * 7,
	};

	response.cookies.set(config.cookies.sessionName, tokens.accessToken, sessionOpts);
	response.cookies.set(config.cookies.csrfName, tokens.csrfToken, {
		...sessionOpts,
		httpOnly: false,
	});

	if (tokens.refreshToken) {
		response.cookies.set(config.cookies.refresh, tokens.refreshToken, {
			...sessionOpts,
			maxAge: 60 * 60 * 24 * 30,
		});
	}
}
