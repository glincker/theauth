import type { AuthConfig, DefaultUser, ResolvedAuthConfig } from "./types.js";

const DEFAULT_COOKIE_CACHE_MAX_AGE_MS = 5 * 60 * 1000; // 5 minutes
const DEFAULT_EXPIRY_REFRESH_BUFFER_S = 60;
const MIN_SECRET_BYTES = 32;

const secrets = new WeakMap<object, string>();

/**
 * Returns the signing secret bound to a config created by createAuthConfig, or undefined for any
 * object that did not come from it (callers must then fail closed). Kept out of the config's own
 * properties so logging or spreading the config never leaks it.
 */
export function getConfigSecret(config: object): string | undefined {
	return secrets.get(config);
}

/**
 * Factory that resolves defaults and returns an immutable config object.
 *
 * @example
 * ```ts
 * // src/lib/auth/config.ts
 * import "server-only";
 * import { createAuthConfig } from "@glinr/theauth-nextjs-auth";
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
	if (
		typeof input.secret !== "string" ||
		new TextEncoder().encode(input.secret).length < MIN_SECRET_BYTES
	) {
		throw new Error(
			`[theauth-nextjs-auth] \`secret\` is required and must be at least ${MIN_SECRET_BYTES} bytes. Generate one with: openssl rand -base64 48`,
		);
	}
	// `isProd` only influences cookie NAMES (the __Host- prefix). It never controls `Secure`.
	const isProd = input.isProd ?? process.env.NODE_ENV === "production";
	// Secure is on unless the caller explicitly opts out (localhost development over plain http).
	const secure = input.secure !== false;
	const useHostPrefix = secure && isProd;

	const sessionPrefix = input.cookies?.sessionPrefix ?? "glinr";
	const refreshCookieName = input.cookies?.refresh ?? `${sessionPrefix}-refresh-token`;

	const sessionName = useHostPrefix ? `__Host-${sessionPrefix}-token` : `${sessionPrefix}-token`;
	const csrfName = useHostPrefix ? `__Host-${sessionPrefix}-csrf` : `${sessionPrefix}-csrf`;
	const cacheName = useHostPrefix
		? `__Host-${sessionPrefix}-session-cache`
		: `${sessionPrefix}-session-cache`;

	const defaultMapUser = (raw: unknown): TUser | null => {
		if (raw === null || raw === undefined) return null;
		return raw as TUser;
	};

	const resolved: ResolvedAuthConfig<TUser> = {
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
		secure,
	};
	secrets.set(resolved, input.secret);
	return resolved;
}
