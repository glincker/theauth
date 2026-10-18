/** Edge-safe cookie attribute builders shared by cookies.ts, refresh.ts and middleware.ts. */

import type { ResolvedAuthConfig } from "./types.js";

export interface CookieAttrs {
	httpOnly: boolean;
	secure: boolean;
	sameSite: "lax";
	path: "/";
	maxAge: number;
}

export const SESSION_MAX_AGE_S = 60 * 60 * 24 * 7;
export const REFRESH_MAX_AGE_S = 60 * 60 * 24 * 30;

/**
 * Secure unless the config opted out (`secure: false`), and always Secure when the request is
 * https. Never derived from NODE_ENV. `https` comes from the request URL or x-forwarded-proto;
 * a spoofed value can only turn Secure ON, never off.
 */
export function resolveSecure<TUser>(config: ResolvedAuthConfig<TUser>, https = false): boolean {
	return config.secure || https;
}

export function sessionCookieAttrs<TUser>(
	config: ResolvedAuthConfig<TUser>,
	https = false,
): CookieAttrs {
	return {
		httpOnly: true,
		secure: resolveSecure(config, https),
		sameSite: "lax",
		path: "/",
		maxAge: SESSION_MAX_AGE_S,
	};
}

/** True when an x-forwarded-proto header value (possibly a list) says https. */
export function isHttpsForwarded(value: string | null | undefined): boolean {
	return value?.split(",")[0]?.trim().toLowerCase() === "https";
}
