import "server-only";

import { getCsrfToken, getSessionToken } from "./cookies.js";
import type { ResolvedAuthConfig } from "./types.js";

interface BuildAuthHeadersOptions {
	/** Include Authorization: Bearer <token>. Default: true. */
	withAuth?: boolean;
	/** Include X-CSRF-Token + Cookie echo. Default: true. */
	withCsrf?: boolean;
}

/**
 * Builds HTTP headers for SERVER → backend calls.
 *
 * Includes: Content-Type, Origin, X-Client-Origin, X-Tenant-Domain,
 * Authorization Bearer (when withAuth), X-CSRF-Token + Cookie echo (when withCsrf).
 *
 * IMPORTANT: Do NOT use these in browser-side fetches. X-Client-Origin
 * triggers a CORS preflight that backends typically reject from browser
 * clients. Use buildClientHeaders() for client-side fetches instead.
 */
export async function buildAuthHeaders<TUser>(
	config: ResolvedAuthConfig<TUser>,
	opts: BuildAuthHeadersOptions = {},
): Promise<Record<string, string>> {
	const { withAuth = true, withCsrf = true } = opts;

	const headers: Record<string, string> = {
		"Content-Type": "application/json",
		Accept: "application/json",
		Origin: config.appUrl,
		"X-Client-Origin": config.appUrl,
	};

	if (config.tenantDomain) {
		headers["X-Tenant-Domain"] = config.tenantDomain;
	}

	if (withAuth) {
		const token = await getSessionToken(config);
		if (token) {
			headers.Authorization = `Bearer ${token}`;
		}
	}

	if (withCsrf) {
		const csrf = await getCsrfToken(config);
		if (csrf) {
			headers["X-CSRF-Token"] = csrf;
			// Synthesise the non-prefixed cookie name for backends that compare via
			// the Cookie header value directly (CSRF double-submit filter pattern).
			headers.Cookie = `${config.cookies.sessionPrefix}-csrf=${csrf}`;
		}
	}

	return headers;
}

/**
 * Builds HTTP headers for BROWSER → backend fetches.
 * Safe to import from "use client" components.
 *
 * Does NOT include Origin or X-Client-Origin — the browser sets Origin
 * automatically on cross-origin requests. Does NOT include auth headers —
 * the browser sends auth cookies automatically.
 */
export function buildClientHeaders<TUser>(
	config: ResolvedAuthConfig<TUser>,
): Record<string, string> {
	const headers: Record<string, string> = {
		"Content-Type": "application/json",
	};
	if (config.tenantDomain) {
		headers["X-Tenant-Domain"] = config.tenantDomain;
	}
	return headers;
}
