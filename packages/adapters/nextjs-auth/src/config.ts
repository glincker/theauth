import type { AuthConfig, DefaultUser, ResolvedAuthConfig } from "./types.js";

const DEFAULT_COOKIE_CACHE_MAX_AGE_MS = 5 * 60 * 1000; // 5 minutes
const DEFAULT_EXPIRY_REFRESH_BUFFER_S = 60;

/**
 * Factory that resolves defaults and returns an immutable config object.
 *
 * @example
 * ```ts
 * // src/lib/auth/config.ts
 * import "server-only";
 * import { createAuthConfig } from "@kavachos/nextjs-auth";
 *
 * export const authConfig = createAuthConfig({
 *   backendUrl: process.env.NEXT_PUBLIC_API_BASE_URL!,
 *   appUrl: process.env.NEXT_PUBLIC_APP_URL!,
 *   tenantDomain: "myapp.com",
 *   mapUser: (raw) => {
 *     if (!raw || typeof raw !== "object") return null;
 *     const r = raw as Record<string, unknown>;
 *     return { id: String(r.id), email: String(r.email ?? ""), name: String(r.name ?? "") };
 *   },
 * });
 * ```
 */
export function createAuthConfig<TUser = DefaultUser>(
	input: AuthConfig<TUser>,
): ResolvedAuthConfig<TUser> {
	const isProd = input.isProd ?? process.env.NODE_ENV === "production";

	const sessionPrefix = input.cookies?.sessionPrefix ?? "glinr";
	const refreshCookieName = input.cookies?.refresh ?? `${sessionPrefix}-refresh-token`;

	const sessionName = isProd ? `__Host-${sessionPrefix}-token` : `${sessionPrefix}-token`;
	const csrfName = isProd ? `__Host-${sessionPrefix}-csrf` : `${sessionPrefix}-csrf`;
	const cacheName = `${sessionPrefix}-session-cache`;

	const defaultMapUser = (raw: unknown): TUser | null => {
		if (raw === null || raw === undefined) return null;
		return raw as TUser;
	};

	return {
		backendUrl: input.backendUrl.replace(/\/$/, ""),
		appUrl: input.appUrl.replace(/\/$/, ""),
		tenantDomain: input.tenantDomain ?? "",
		endpoints: {
			me: input.endpoints?.me ?? "/api/auth/me",
			refresh: input.endpoints?.refresh ?? "/api/auth/refresh",
			signOut: input.endpoints?.signOut ?? "/api/auth/logout",
		},
		cookies: {
			sessionPrefix,
			refresh: refreshCookieName,
			sessionName,
			csrfName,
			cacheName,
		},
		cookieCacheMaxAgeMs: input.cookieCacheMaxAgeMs ?? DEFAULT_COOKIE_CACHE_MAX_AGE_MS,
		expiryRefreshBufferS: input.expiryRefreshBufferS ?? DEFAULT_EXPIRY_REFRESH_BUFFER_S,
		mapUser: input.mapUser ?? defaultMapUser,
		isProd,
	};
}
