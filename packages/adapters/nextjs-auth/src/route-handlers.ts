import "server-only";

import { cookies } from "next/headers";
import { buildAuthHeaders } from "./headers.js";
import type { ResolvedAuthConfig } from "./types.js";

/**
 * Creates a Server Action that signs the user out:
 * 1. Calls the backend logout endpoint (best-effort, failure is ignored).
 * 2. Clears all session, CSRF, refresh, and cache cookies.
 *
 * @example
 * ```ts
 * // src/lib/auth/actions.ts
 * import "server-only";
 * import { createSignOutAction } from "@kavachos/nextjs-auth";
 * import { authConfig } from "./config";
 *
 * export const signOut = createSignOutAction(authConfig);
 *
 * // In a client component:
 * <button onClick={() => signOut()}>Sign out</button>
 * ```
 */
export function createSignOutAction<TUser>(
	config: ResolvedAuthConfig<TUser>,
): () => Promise<{ success: boolean }> {
	async function signOutAction(): Promise<{ success: boolean }> {
		"use server";

		try {
			const headers = await buildAuthHeaders(config, {
				withAuth: true,
				withCsrf: false,
			});
			await fetch(`${config.backendUrl}${config.endpoints.signOut}`, {
				method: "POST",
				headers,
			});
		} catch {
			// Best-effort — local cookie clearing is the source of truth.
		}

		const store = await cookies();
		const { sessionPrefix } = config.cookies;
		store.delete(`__Host-${sessionPrefix}-token`);
		store.delete(`${sessionPrefix}-token`);
		store.delete(`__Host-${sessionPrefix}-csrf`);
		store.delete(`${sessionPrefix}-csrf`);
		store.delete(config.cookies.refresh);
		store.delete(config.cookies.cacheName);

		return { success: true };
	}

	return signOutAction;
}
