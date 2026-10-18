import "server-only";

import { clearAllAuthCookiesFromStore } from "./cookies.js";
import { buildAuthHeaders } from "./headers.js";
import type { ResolvedAuthConfig } from "./types.js";

/**
 * Returns a sign-out function that clears session cookies and best-effort logs out on the backend.
 * Wrap it in your own "use server" file. The adapter does not inline the directive, so it stays
 * safe to import from client module graphs.
 */
export function createSignOutHandler<TUser>(
	config: ResolvedAuthConfig<TUser>,
): () => Promise<{ success: boolean }> {
	return async function signOut(): Promise<{ success: boolean }> {
		// Best-effort backend logout. Local cookie clearing is the source of truth.
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
			// Ignored, the local cookie clear is the critical part
		}

		await clearAllAuthCookiesFromStore(config);

		return { success: true };
	};
}

/** @deprecated Use createSignOutHandler instead. The inline "use server" directive breaks in client component graphs. */
export const createSignOutAction = createSignOutHandler;
