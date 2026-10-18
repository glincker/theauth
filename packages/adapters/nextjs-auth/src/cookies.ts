import "server-only";

import { cookies, headers } from "next/headers";
import type { NextResponse } from "next/server";
import { getConfigSecret } from "./config.js";
import { isHttpsForwarded, REFRESH_MAX_AGE_S, sessionCookieAttrs } from "./cookie-options.js";
import { decodeSessionCache, encodeSessionCache } from "./session-cache-codec.js";
import type { ResolvedAuthConfig, SessionCacheEntry } from "./types.js";

/** Returns the session access token, checking prefixed + unprefixed names. */
export async function getSessionToken<TUser>(config: ResolvedAuthConfig<TUser>): Promise<string> {
	const store = await cookies();
	// Always check both __Host- variant and plain variant for migration safety.
	const prefixedName = `__Host-${config.cookies.sessionPrefix}-token`;
	const plainName = `${config.cookies.sessionPrefix}-token`;
	return store.get(prefixedName)?.value ?? store.get(plainName)?.value ?? "";
}

/** Returns the CSRF token, checking prefixed + unprefixed names. */
export async function getCsrfToken<TUser>(config: ResolvedAuthConfig<TUser>): Promise<string> {
	const store = await cookies();
	const prefixedName = `__Host-${config.cookies.sessionPrefix}-csrf`;
	const plainName = `${config.cookies.sessionPrefix}-csrf`;
	return store.get(prefixedName)?.value ?? store.get(plainName)?.value ?? "";
}

/** Cheap check: does the request carry a session access token? */
export async function hasSessionCookie<TUser>(config: ResolvedAuthConfig<TUser>): Promise<boolean> {
	const token = await getSessionToken(config);
	return token.length > 0;
}

// Session cache cookie
//
// Instead of calling the backend on every RSC render, we store a signed blob
// {user, expiresAt, stampedAt} in a short-lived cookie. The value is HMAC-SHA256 signed with the
// required config secret, bound to a hash of the current session token and to an expiry (see
// session-cache-codec). Anything that fails verification, including legacy unsigned JSON from
// 0.2.0 and earlier, is treated as "no cache" and getServerSession asks the backend instead.
//
// The payload is signed, not encrypted: session data (user id, email, name) is readable by anyone
// who can read the cookie. It is httpOnly, so page JavaScript cannot.

async function requestIsHttps(): Promise<boolean> {
	try {
		const h = await headers();
		return isHttpsForwarded(h.get("x-forwarded-proto"));
	} catch {
		return false;
	}
}

export async function readSessionCache<TUser>(
	config: ResolvedAuthConfig<TUser>,
): Promise<SessionCacheEntry<TUser> | null> {
	if (config.cookieCacheMaxAgeMs === 0) return null;
	const secret = getConfigSecret(config);
	if (!secret) return null;
	// A cache entry is only meaningful together with the session token it was issued for.
	const token = await getSessionToken(config);
	if (!token) return null;
	const store = await cookies();
	const raw = store.get(config.cookies.cacheName)?.value;
	if (!raw) return null;
	try {
		return await decodeSessionCache<TUser>(secret, token, raw, config.cookieCacheMaxAgeMs);
	} catch {
		return null;
	}
}

/** Writes the signed cache cookie, bound to `token`. Best-effort: never throws. */
export async function writeSessionCache<TUser>(
	config: ResolvedAuthConfig<TUser>,
	entry: SessionCacheEntry<TUser>,
	token: string,
): Promise<void> {
	if (config.cookieCacheMaxAgeMs === 0) return;
	const secret = getConfigSecret(config);
	if (!secret || !token) return;
	try {
		const encoded = await encodeSessionCache(secret, token, entry, config.cookieCacheMaxAgeMs);
		if (!encoded) return; // too large or already expired: skip rather than set a broken cookie
		const store = await cookies();
		store.set(config.cookies.cacheName, encoded.value, {
			...sessionCookieAttrs(config, await requestIsHttps()),
			sameSite: "lax",
			maxAge: encoded.maxAgeS,
		});
	} catch {
		// Silently fail if called from a Server Component (where cookie writes
		// are dropped on the floor). The cache is best-effort.
	}
}

export async function clearSessionCache<TUser>(config: ResolvedAuthConfig<TUser>): Promise<void> {
	try {
		const store = await cookies();
		store.set(config.cookies.cacheName, "", {
			...sessionCookieAttrs(config, await requestIsHttps()),
			maxAge: 0,
		});
	} catch {}
}

// Cookie write helpers (response-based, for Route Handlers + middleware)

interface SessionCookieValues {
	accessToken: string;
	csrfToken: string;
	refreshToken?: string;
}

/** Sets all session cookies on a NextResponse: __Host- prefix in prod, plain names in dev. */
export function setSessionCookies<TUser>(
	response: NextResponse,
	{ accessToken, csrfToken, refreshToken }: SessionCookieValues,
	config: ResolvedAuthConfig<TUser>,
): void {
	const sessionOpts = sessionCookieAttrs(config);

	response.cookies.set(config.cookies.sessionName, accessToken, sessionOpts);

	// CSRF double-submit: httpOnly=false so JS can read and echo in X-CSRF-Token.
	response.cookies.set(config.cookies.csrfName, csrfToken, {
		...sessionOpts,
		httpOnly: false,
	});

	if (refreshToken) {
		response.cookies.set(config.cookies.refresh, refreshToken, {
			...sessionOpts,
			maxAge: REFRESH_MAX_AGE_S,
		});
	}
}

/** Clears all auth cookies on a NextResponse, both __Host- and plain variants, for clean migration. */
export function clearAllAuthCookies<TUser>(
	response: NextResponse,
	config: ResolvedAuthConfig<TUser>,
): void {
	const { sessionPrefix } = config.cookies;
	// Secure is required for the browser to accept an expiry of a __Host- cookie.
	const expire = { path: "/", maxAge: 0, secure: config.secure, httpOnly: true } as const;
	for (const name of [
		`__Host-${sessionPrefix}-token`,
		`${sessionPrefix}-token`,
		`__Host-${sessionPrefix}-csrf`,
		`${sessionPrefix}-csrf`,
		config.cookies.refresh,
		config.cookies.cacheName,
		`${sessionPrefix}-session-cache`,
	]) {
		response.cookies.set(name, "", expire);
	}
}

/** Clears session cookies via next/headers cookies() store (server actions). */
export async function clearAllAuthCookiesFromStore<TUser>(
	config: ResolvedAuthConfig<TUser>,
): Promise<void> {
	const store = await cookies();
	const { sessionPrefix } = config.cookies;
	const expire = { path: "/", maxAge: 0, secure: config.secure, httpOnly: true } as const;
	for (const name of [
		`__Host-${sessionPrefix}-token`,
		`${sessionPrefix}-token`,
		`__Host-${sessionPrefix}-csrf`,
		`${sessionPrefix}-csrf`,
		config.cookies.refresh,
		config.cookies.cacheName,
		`${sessionPrefix}-session-cache`,
	]) {
		store.set(name, "", expire);
	}
}
