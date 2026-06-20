/**
 * API key auth adapter for TheAuth.
 *
 * Reads an API key from a request header (default: `x-api-key`) and delegates
 * validation to a caller-supplied function.  Useful for service-to-service
 * calls and developer tooling where session cookies are not appropriate.
 *
 * @example
 * ```typescript
 * import { apiKeyAdapter } from 'theauth/auth';
 *
 * const kavach = await createKavach({
 *   database: { provider: 'sqlite', url: 'kavach.db' },
 *   auth: apiKeyAdapter({
 *     validateKey: async (key) => {
 *       const record = await db.apiKeys.findUnique({ where: { key } });
 *       if (!record || record.revokedAt) return null;
 *       return { userId: record.userId, email: record.ownerEmail };
 *     },
 *   }),
 * });
 * ```
 *
 * @example Custom header
 * ```typescript
 * const adapter = apiKeyAdapter({
 *   header: 'authorization', // e.g. "Bearer sk-..."
 *   validateKey: async (key) => { ... },
 * });
 * ```
 */

import type { AuthAdapter, ResolvedUser } from "../types.js";

export interface ApiKeyAdapterOptions {
	/**
	 * The request header that carries the API key.
	 * Defaults to `x-api-key`.
	 */
	header?: string;

	/**
	 * Validate the extracted API key.
	 *
	 * Return `{ userId, email?, name? }` on success, or `null` when the key is
	 * unknown, revoked, or expired.
	 */
	validateKey: (key: string) => Promise<{
		userId: string;
		email?: string;
		name?: string;
	} | null>;
}

/**
 * Create an `AuthAdapter` that reads an API key from a request header and
 * validates it via the supplied `validateKey` function.
 *
 * Returns `null` when:
 * - The configured header is absent or empty
 * - `validateKey` returns `null`
 * - `validateKey` throws
 */
export function apiKeyAdapter(options: ApiKeyAdapterOptions): AuthAdapter {
	const headerName = (options.header ?? "x-api-key").toLowerCase();

	return {
		async resolveUser(request: Request): Promise<ResolvedUser | null> {
			const key = request.headers.get(headerName);
			if (!key || key.trim() === "") return null;

			let result: { userId: string; email?: string; name?: string } | null;

			try {
				result = await options.validateKey(key.trim());
			} catch {
				return null;
			}

			if (!result) return null;

			return {
				id: result.userId,
				...(result.email !== undefined && { email: result.email }),
				...(result.name !== undefined && { name: result.name }),
			};
		},
	};
}
