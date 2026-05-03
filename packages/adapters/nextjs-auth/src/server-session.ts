import "server-only";

import { cache } from "react";
import { getSessionToken, readSessionCache, writeSessionCache } from "./cookies.js";
import { buildAuthHeaders } from "./headers.js";
import { readJwtExp } from "./jwt.js";
import { refreshSession } from "./refresh.js";
import type { AuthSession, ResolvedAuthConfig, SessionCacheEntry } from "./types.js";

interface MeResponse {
	[key: string]: unknown;
}

/**
 * Fetches the authenticated session.
 *
 * Performance strategy (better-auth-inspired):
 * 1. Per-request memo via React.cache() — repeated calls in the same render
 *    pass return instantly without any I/O.
 * 2. Cookie cache — if the session cache cookie is fresher than
 *    config.cookieCacheMaxAgeMs, return cached user data without a backend call.
 * 3. Backend call to config.endpoints.me — on 401, attempts one refresh;
 *    on second 401, returns null.
 * 4. Writes the session cache cookie so subsequent RSCs skip the backend call.
 *
 * Cookie cache TTL default: 5 minutes (matches better-auth's cookieCache.maxAge).
 */
export const getServerSession = cache(_getServerSessionImpl) as <TUser>(
	config: ResolvedAuthConfig<TUser>,
) => Promise<AuthSession<TUser> | null>;

async function _getServerSessionImpl<TUser>(
	config: ResolvedAuthConfig<TUser>,
): Promise<AuthSession<TUser> | null> {
	// 1. Cookie cache check
	const cached = await readSessionCache(config);
	if (cached) {
		return {
			user: cached.user,
			expiresAt: cached.expiresAt ? new Date(cached.expiresAt) : null,
		};
	}

	// 2. Need a token to call /me
	const token = await getSessionToken(config);
	if (!token) return null;

	// 3. Call /me
	const session = await _fetchMe(config);
	if (session) {
		await _stampSessionCache(config, session);
		return session;
	}

	// 4. 401 — try refresh once
	const refreshed = await refreshSession(config);
	if (!refreshed) return null;

	const retrySession = await _fetchMe(config);
	if (retrySession) {
		await _stampSessionCache(config, retrySession);
	}
	return retrySession;
}

async function _fetchMe<TUser>(
	config: ResolvedAuthConfig<TUser>,
): Promise<AuthSession<TUser> | null> {
	const headers = await buildAuthHeaders(config, { withAuth: true, withCsrf: false });

	let response: Response;
	try {
		response = await fetch(`${config.backendUrl}${config.endpoints.me}`, {
			headers,
			cache: "no-store",
		});
	} catch {
		return null;
	}

	if (!response.ok) return null;

	let raw: MeResponse;
	try {
		raw = (await response.json()) as MeResponse;
	} catch {
		return null;
	}

	const user = config.mapUser(raw);
	if (!user) return null;

	// Parse exp from the current access token for the session's expiresAt.
	const token = await getSessionToken(config);
	const expS = token ? readJwtExp(token) : null;
	const expiresAt = expS ? new Date(expS * 1000) : null;

	return { user, expiresAt };
}

async function _stampSessionCache<TUser>(
	config: ResolvedAuthConfig<TUser>,
	session: AuthSession<TUser>,
): Promise<void> {
	const entry: SessionCacheEntry<TUser> = {
		user: session.user,
		expiresAt: session.expiresAt ? session.expiresAt.toISOString() : null,
		stampedAt: Date.now(),
	};
	await writeSessionCache(config, entry);
}
