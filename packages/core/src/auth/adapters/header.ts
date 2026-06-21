/**
 * Header-based auth adapter.
 *
 * Extracts the user ID from a trusted request header.  Designed for services
 * deployed behind an auth proxy (e.g. Nginx, Cloudflare Access, AWS ALB) that
 * injects a verified user-identity header before forwarding requests.
 *
 * @example Default header (`X-User-Id`)
 * ```typescript
 * import { headerAuth } from '@glinr/theauth/auth';
 *
 * const adapter = headerAuth();
 * ```
 *
 * @example Custom header
 * ```typescript
 * const adapter = headerAuth({ header: 'X-Authenticated-User' });
 * ```
 *
 * IMPORTANT: Only use this adapter when the header cannot be forged by the
 * client (i.e. the upstream proxy strips or overrides it).
 */

import type { AuthAdapter, ResolvedUser } from "../types.js";

export interface HeaderAuthOptions {
	/**
	 * Name of the HTTP header that carries the user ID.
	 * Defaults to `X-User-Id`.
	 */
	header?: string;
}

/**
 * Create an `AuthAdapter` that extracts the user identity from a request header.
 *
 * Returns `null` when the header is absent or its value is empty.
 */
export function headerAuth(options?: HeaderAuthOptions): AuthAdapter {
	const headerName = options?.header ?? "X-User-Id";
	// Normalise to lower-case for case-insensitive lookup via the Headers API.
	const normalised = headerName.toLowerCase();

	return {
		async resolveUser(request: Request): Promise<ResolvedUser | null> {
			const value = request.headers.get(normalised);
			if (!value || value.trim() === "") return null;

			return { id: value.trim() };
		},
	};
}
