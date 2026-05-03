import "server-only";

import { cookies } from "next/headers";
import { clearSessionCache } from "./cookies.js";
import { generateCsrfToken } from "./csrf.js";
import type { RefreshResult, ResolvedAuthConfig } from "./types.js";

interface BackendRefreshResponse {
	accessToken?: string;
	refreshToken?: string;
	expiresIn?: number;
}

/**
 * Calls the backend refresh endpoint with the stored refresh-token cookie.
 *
 * On success: writes fresh access + CSRF cookies (and optionally a rotated
 * refresh token) via next/headers cookies(). Returns the new token values so
 * callers can immediately retry with fresh credentials.
 *
 * On failure:
 *   - Network error → returns null, does NOT clear cookies (may be transient).
 *   - 401/403 → clears all session cookies, returns null.
 *
 * Note: cookies() writes are only honoured from Server Actions and Route
 * Handlers. Calling from a Server Component will succeed in-memory for this
 * request but the browser will not receive Set-Cookie headers.
 */
export async function refreshSession<TUser>(
	config: ResolvedAuthConfig<TUser>,
): Promise<RefreshResult | null> {
	const store = await cookies();
	const refreshToken = store.get(config.cookies.refresh)?.value;

	if (!refreshToken) return null;

	let response: Response;
	try {
		response = await fetch(`${config.backendUrl}${config.endpoints.refresh}`, {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				Accept: "application/json",
				Origin: config.appUrl,
				"X-Client-Origin": config.appUrl,
				...(config.tenantDomain ? { "X-Tenant-Domain": config.tenantDomain } : {}),
			},
			body: JSON.stringify({ refreshToken }),
			cache: "no-store",
		});
	} catch {
		// Network error — let caller treat as retriable, keep cookies.
		return null;
	}

	if (!response.ok) {
		if (response.status === 401 || response.status === 403) {
			await _clearSessionCookiesFromStore(config, store);
		}
		return null;
	}

	let data: BackendRefreshResponse;
	try {
		data = (await response.json()) as BackendRefreshResponse;
	} catch {
		return null;
	}

	if (!data.accessToken) return null;

	const newCsrf = generateCsrfToken();

	const sessionOpts = {
		httpOnly: true,
		secure: config.isProd,
		sameSite: "lax" as const,
		path: "/",
		maxAge: 60 * 60 * 24 * 7, // 7 days
	};

	store.set(config.cookies.sessionName, data.accessToken, sessionOpts);
	store.set(config.cookies.csrfName, newCsrf, {
		...sessionOpts,
		httpOnly: false,
	});

	if (data.refreshToken) {
		store.set(config.cookies.refresh, data.refreshToken, {
			...sessionOpts,
			maxAge: 60 * 60 * 24 * 30, // 30 days
		});
	}

	// Invalidate the session cache so the next getServerSession re-validates.
	await clearSessionCache(config);

	return {
		accessToken: data.accessToken,
		refreshToken: data.refreshToken,
		csrfToken: newCsrf,
	};
}

async function _clearSessionCookiesFromStore<TUser>(
	config: ResolvedAuthConfig<TUser>,
	store: Awaited<ReturnType<typeof cookies>>,
): Promise<void> {
	const { sessionPrefix } = config.cookies;
	store.delete(`__Host-${sessionPrefix}-token`);
	store.delete(`${sessionPrefix}-token`);
	store.delete(`__Host-${sessionPrefix}-csrf`);
	store.delete(`${sessionPrefix}-csrf`);
	store.delete(config.cookies.refresh);
	store.delete(config.cookies.cacheName);
}
