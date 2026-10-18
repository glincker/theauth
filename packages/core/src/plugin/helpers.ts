/** Shared helpers for TheAuth plugin endpoints. */

import { serializeCookie, serializeCookieDeletion } from "../session/cookie.js";
import type { Session } from "../session/session.js";
import { buildSessionCookie } from "../session/session-cookie.js";

/** Create a JSON response with proper headers. */
export function json(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "Content-Type": "application/json" },
	});
}

/** Parse JSON body from a request. Returns a discriminated union so callers get clear error feedback instead of a silent empty object. */
export async function parseBody(
	request: Request,
): Promise<{ ok: true; data: Record<string, unknown> } | { ok: false; response: Response }> {
	try {
		const data = (await request.json()) as Record<string, unknown>;
		return { ok: true, data };
	} catch {
		return {
			ok: false,
			response: json({ error: "Invalid JSON body" }, 400),
		};
	}
}

/** Extract a cookie value from a request. */
export function getCookie(request: Request, name: string): string | null {
	const header = request.headers.get("cookie");
	if (!header) return null;
	const match = header.match(new RegExp(`(?:^|;\\s*)${name}=([^;]*)`));
	return match?.[1] ? decodeURIComponent(match[1]) : null;
}

/** Build a Set-Cookie header value through the shared cookie serializer. */
export function buildSetCookie(
	name: string,
	value: string,
	maxAge: number,
	path = "/",
	secure = true,
): string {
	return serializeCookie(name, value, { maxAge, path, secure, httpOnly: true, sameSite: "lax" });
}

/**
 * Session cookie for a freshly signed in session. `rememberMe: false` sends a browser session cookie (no `Max-Age`), `true` a persistent one until `session.expiresAt`, and an unset choice keeps the persistent legacy cookie.
 */
export function buildSessionSetCookie(
	name: string,
	token: string,
	session: Pick<Session, "expiresAt" | "rememberMe">,
	secure = true,
): string {
	return buildSessionCookie(name, token, session, {
		path: "/",
		secure,
		httpOnly: true,
		sameSite: "lax",
	});
}

/** Read an optional `rememberMe` choice: a boolean, or the strings "true"/"false" (query strings). Anything else is unset, so the default is unchanged. */
export function parseRememberMe(value: unknown): boolean | undefined {
	if (value === true || value === "true") return true;
	if (value === false || value === "false") return false;
	return undefined;
}

/** Build a Set-Cookie header that clears a cookie. */
export function buildClearCookie(name: string, path = "/", secure = true): string {
	return serializeCookieDeletion(name, { path, secure, httpOnly: true, sameSite: "lax" });
}

/** Extract a Bearer token from the Authorization header, or fall back to a named cookie. */
export function extractToken(request: Request, cookieName = "theauth_session"): string | null {
	const authHeader = request.headers.get("authorization");
	if (authHeader?.startsWith("Bearer ")) {
		return authHeader.slice(7);
	}
	return getCookie(request, cookieName);
}
