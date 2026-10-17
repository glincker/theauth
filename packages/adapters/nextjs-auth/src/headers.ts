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
 * Headers for SERVER to backend calls. Do NOT use in browser fetches: X-Client-Origin triggers a
 * CORS preflight that backends typically reject. Use buildClientHeaders() there instead.
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
			// Also send the unprefixed cookie name for backends that compare the Cookie header directly.
			headers.Cookie = `${config.cookies.sessionPrefix}-csrf=${csrf}`;
		}
	}

	return headers;
}

/**
 * Headers for BROWSER to backend fetches. Safe in "use client" components. Origin and auth
 * headers are not set here: the browser sends them itself.
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
