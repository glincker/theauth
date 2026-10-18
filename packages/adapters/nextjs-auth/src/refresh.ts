import "server-only";

import { cookies } from "next/headers";
import { getConfigSecret } from "./config.js";
import { REFRESH_MAX_AGE_S, sessionCookieAttrs } from "./cookie-options.js";
import { clearAllAuthCookiesFromStore, clearSessionCache } from "./cookies.js";
import { createCsrfToken } from "./csrf.js";
import { createSessionMarker } from "./session-marker.js";
import type { RefreshResult, ResolvedAuthConfig } from "./types.js";

interface BackendRefreshResponse {
	accessToken?: string;
	refreshToken?: string;
	expiresIn?: number;
}

/**
 * Refreshes the access token from the stored refresh-token cookie and writes fresh cookies.
 * Network errors return null without clearing cookies (they may be transient). 401/403 clears them.
 * cookies() writes only reach the browser from Server Actions and Route Handlers.
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
		// Network error: let the caller treat it as retriable and keep cookies.
		return null;
	}

	if (!response.ok) {
		if (response.status === 401 || response.status === 403) {
			await clearAllAuthCookiesFromStore(config);
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

	const secret = getConfigSecret(config);
	if (!secret) return null;
	const newCsrf = await createCsrfToken(secret, data.accessToken);

	const sessionOpts = sessionCookieAttrs(config);

	store.set(config.cookies.sessionName, data.accessToken, sessionOpts);
	store.set(
		config.cookies.markerName,
		await createSessionMarker(secret, data.accessToken),
		sessionOpts,
	);
	store.set(config.cookies.csrfName, newCsrf, {
		...sessionOpts,
		httpOnly: false,
	});

	if (data.refreshToken) {
		store.set(config.cookies.refresh, data.refreshToken, {
			...sessionOpts,
			maxAge: REFRESH_MAX_AGE_S,
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
