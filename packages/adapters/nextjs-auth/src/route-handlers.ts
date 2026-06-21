import "server-only";

import { cookies } from "next/headers";
import { buildAuthHeaders } from "./headers.js";
import type { ResolvedAuthConfig } from "./types.js";

/**
 * Returns an async function that signs the user out: POSTs to the backend
 * sign-out endpoint (best-effort) and clears all session/csrf/refresh
 * cookies on the response.
 *
 * IMPORTANT — usage:
 *   The adapter does NOT inline a `"use server"` directive. Wrap the returned
 *   handler in your OWN server-action file:
 *
 *     // app/auth/actions.ts
 *     "use server";
 *     import { createSignOutHandler } from "@glinr/theauth-nextjs-auth";
 *     import { authConfig } from "@/lib/auth/config.server";
 *     export const signOut = createSignOutHandler(authConfig);
 *
 *   This keeps the directive in your code (where Next.js can statically
 *   analyse it) and lets the adapter be safely imported from any client/
 *   server module without polluting client bundles.
 */
export function createSignOutHandler<TUser>(
	config: ResolvedAuthConfig<TUser>,
): () => Promise<{ success: boolean }> {
	return async function signOut(): Promise<{ success: boolean }> {
		// Best-effort backend logout — local cookie clearing is the source of truth.
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
			// Ignore — local cookie clear is the critical part
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
	};
}

// Backward-compat alias — DEPRECATED, will be removed in v0.2
/** @deprecated Use createSignOutHandler instead. createSignOutAction's inline
 * "use server" directive breaks when the adapter is imported by a client
 * component graph. */
export const createSignOutAction = createSignOutHandler;
