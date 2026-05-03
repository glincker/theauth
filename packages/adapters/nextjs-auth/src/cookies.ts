import "server-only";

import { cookies } from "next/headers";
import type { NextResponse } from "next/server";
import type { ResolvedAuthConfig, SessionCacheEntry } from "./types.js";

// ---------------------------------------------------------------------------
// Cookie read helpers (server-only)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Session cache cookie (better-auth-inspired cookie cache)
// ---------------------------------------------------------------------------
//
// Instead of calling the backend on every RSC render, we store a lightweight
// JSON blob {user, expiresAt, stampedAt} in a short-lived cookie. If the
// cookie is fresher than cookieCacheMaxAgeMs we return it immediately.
//
// v0.1: plain JSON (no HMAC signing). The cookie is httpOnly+sameSite=lax so
// it can only be set by the server — a passive attacker reading TLS can see
// it but cannot forge it (they'd need the access token anyway). An active
// MITM could poison it, but that already requires breaking TLS. v0.2 will
// add HMAC-SHA256 signing for defence-in-depth.
//
// Tradeoff: session data (user id, email, name) is stored in a cookie. Any
// code path that can read cookies will see this. For most apps this is
// acceptable since the same information is in the JWT claims anyway.

export async function readSessionCache<TUser>(
	config: ResolvedAuthConfig<TUser>,
): Promise<SessionCacheEntry<TUser> | null> {
	if (config.cookieCacheMaxAgeMs === 0) return null;
	const store = await cookies();
	const raw = store.get(config.cookies.cacheName)?.value;
	if (!raw) return null;
	try {
		const entry = JSON.parse(raw) as SessionCacheEntry<TUser>;
		const age = Date.now() - entry.stampedAt;
		if (age > config.cookieCacheMaxAgeMs) return null;
		return entry;
	} catch {
		return null;
	}
}

export async function writeSessionCache<TUser>(
	config: ResolvedAuthConfig<TUser>,
	entry: SessionCacheEntry<TUser>,
): Promise<void> {
	if (config.cookieCacheMaxAgeMs === 0) return;
	try {
		const store = await cookies();
		store.set(config.cookies.cacheName, JSON.stringify(entry), {
			httpOnly: true,
			secure: config.isProd,
			sameSite: "lax",
			path: "/",
			maxAge: Math.floor(config.cookieCacheMaxAgeMs / 1000),
		});
	} catch {
		// Silently fail if called from a Server Component (where cookie writes
		// are dropped on the floor). The cache is best-effort.
	}
}

export async function clearSessionCache<TUser>(config: ResolvedAuthConfig<TUser>): Promise<void> {
	try {
		const store = await cookies();
		store.delete(config.cookies.cacheName);
	} catch {
		// ignore
	}
}

// ---------------------------------------------------------------------------
// Cookie write helpers (response-based, for Route Handlers + middleware)
// ---------------------------------------------------------------------------

interface SessionCookieValues {
	accessToken: string;
	csrfToken: string;
	refreshToken?: string;
}

/**
 * Writes all session cookies onto a NextResponse with consistent options.
 * Uses __Host- prefix in prod, plain names in dev.
 */
export function setSessionCookies<TUser>(
	response: NextResponse,
	{ accessToken, csrfToken, refreshToken }: SessionCookieValues,
	config: ResolvedAuthConfig<TUser>,
): void {
	const sessionOpts = {
		httpOnly: true,
		secure: config.isProd,
		sameSite: "lax" as const,
		path: "/",
		maxAge: 60 * 60 * 24 * 7, // 7 days
	};

	response.cookies.set(config.cookies.sessionName, accessToken, sessionOpts);

	// CSRF double-submit: httpOnly=false so JS can read and echo in X-CSRF-Token.
	response.cookies.set(config.cookies.csrfName, csrfToken, {
		...sessionOpts,
		httpOnly: false,
	});

	if (refreshToken) {
		response.cookies.set(config.cookies.refresh, refreshToken, {
			...sessionOpts,
			maxAge: 60 * 60 * 24 * 30, // 30 days
		});
	}
}

/**
 * Clears all auth cookies on a NextResponse.
 * Deletes both __Host- prefixed and plain variants for clean migration.
 */
export function clearAllAuthCookies<TUser>(
	response: NextResponse,
	config: ResolvedAuthConfig<TUser>,
): void {
	const { sessionPrefix } = config.cookies;
	response.cookies.delete(`__Host-${sessionPrefix}-token`);
	response.cookies.delete(`${sessionPrefix}-token`);
	response.cookies.delete(`__Host-${sessionPrefix}-csrf`);
	response.cookies.delete(`${sessionPrefix}-csrf`);
	response.cookies.set(config.cookies.refresh, "", { path: "/", maxAge: 0 });
	response.cookies.set(config.cookies.cacheName, "", { path: "/", maxAge: 0 });
}

/** Clears session cookies via next/headers cookies() store (server actions). */
export async function clearAllAuthCookiesFromStore<TUser>(
	config: ResolvedAuthConfig<TUser>,
): Promise<void> {
	const store = await cookies();
	const { sessionPrefix } = config.cookies;
	store.delete(`__Host-${sessionPrefix}-token`);
	store.delete(`${sessionPrefix}-token`);
	store.delete(`__Host-${sessionPrefix}-csrf`);
	store.delete(`${sessionPrefix}-csrf`);
	store.delete(config.cookies.refresh);
	store.delete(config.cookies.cacheName);
}
