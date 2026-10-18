/**
 * Session cookie lifetime for the remember me choice. Every `Set-Cookie` still goes through `serializeCookie`.
 */

import type { CookieOptions } from "./cookie.js";
import { serializeCookie } from "./cookie.js";
import type { Session } from "./session.js";

/**
 * Build the session cookie for a freshly created session.
 *
 * - `rememberMe: false` writes a browser session cookie (no `Max-Age`, no `Expires`). The server side `expiresAt` still bounds the session.
 * - `rememberMe: true` writes a persistent cookie that lives until `session.expiresAt`.
 * - unset keeps the legacy behavior: persistent for `defaultMaxAge` seconds (or until `expiresAt` when no default is given).
 */
export function buildSessionCookie(
	name: string,
	token: string,
	session: Pick<Session, "expiresAt" | "rememberMe">,
	options: Omit<CookieOptions, "maxAge" | "expires"> & {
		defaultMaxAge?: number;
		now?: number;
	} = {},
): string {
	const { defaultMaxAge, now = Date.now(), ...cookie } = options;
	if (session.rememberMe === false) return serializeCookie(name, token, cookie);
	const remaining = Math.max(0, Math.floor((session.expiresAt.getTime() - now) / 1000));
	const maxAge = session.rememberMe === true ? remaining : (defaultMaxAge ?? remaining);
	return serializeCookie(name, token, { ...cookie, maxAge });
}
