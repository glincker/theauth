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
 * Fetches the authenticated session in three layers: a per-request React.cache() memo, a session
 * cache cookie (fresher than cookieCacheMaxAgeMs skips the backend), then the backend /me call
 * with one refresh on 401. Cookie cache TTL default: 5 minutes (matches better-auth cookieCache.maxAge).
 */
export const getServerSession = cache(_getServerSessionImpl) as <TUser>(
	config: ResolvedAuthConfig<TUser>,
) => Promise<AuthSession<TUser> | null>;

async function _getServerSessionImpl<TUser>(
	config: ResolvedAuthConfig<TUser>,
): Promise<AuthSession<TUser> | null> {
	// No token means no session, whatever any other cookie says.
	const token = await getSessionToken(config);
	if (!token) return null;

	// Only a verified (signed, token-bound, unexpired) cache entry skips the backend.
	const cached = await readSessionCache(config);
	if (cached) {
		return {
			user: cached.user,
			expiresAt: cached.expiresAt ? new Date(cached.expiresAt) : null,
		};
	}

	const session = await _fetchMe(config);
	if (session) {
		await _stampSessionCache(config, session, token);
		return session;
	}

	const refreshed = await refreshSession(config);
	if (!refreshed) return null;

	const retrySession = await _fetchMe(config);
	if (retrySession) {
		await _stampSessionCache(config, retrySession, refreshed.accessToken);
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

	const token = await getSessionToken(config);
	const expS = token ? readJwtExp(token) : null;
	const expiresAt = expS ? new Date(expS * 1000) : null;

	return { user, expiresAt };
}

async function _stampSessionCache<TUser>(
	config: ResolvedAuthConfig<TUser>,
	session: AuthSession<TUser>,
	token: string,
): Promise<void> {
	const entry: SessionCacheEntry<TUser> = {
		user: session.user,
		expiresAt: session.expiresAt ? session.expiresAt.toISOString() : null,
		stampedAt: Date.now(),
	};
	await writeSessionCache(config, entry, token);
}
