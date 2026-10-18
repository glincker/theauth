import "server-only";

import { clearAllAuthCookiesFromStore } from "./cookies.js";
import { verifyCsrfRequest } from "./csrf-verify.js";
import { buildAuthHeaders } from "./headers.js";
import type { ResolvedAuthConfig } from "./types.js";

async function performSignOut<TUser>(config: ResolvedAuthConfig<TUser>): Promise<void> {
	// Best-effort backend logout. Local cookie clearing is the source of truth.
	try {
		const headers = await buildAuthHeaders(config, { withAuth: true, withCsrf: false });
		await fetch(`${config.backendUrl}${config.endpoints.signOut}`, { method: "POST", headers });
	} catch {
		// Ignored, the local cookie clear is the critical part
	}
	await clearAllAuthCookiesFromStore(config);
}

/**
 * Returns a sign-out function that clears session cookies and best-effort logs out on the backend.
 * It is state changing, so it requires the signed CSRF token (the value of the CSRF cookie, which
 * client code can read) as its argument and returns `{ success: false }` without doing anything
 * when it is missing, forged, or from another session.
 * Wrap it in your own "use server" file. The adapter does not inline the directive, so it stays
 * safe to import from client module graphs.
 */
export function createSignOutHandler<TUser>(
	config: ResolvedAuthConfig<TUser>,
): (csrfToken?: string) => Promise<{ success: boolean }> {
	return async function signOut(csrfToken?: string): Promise<{ success: boolean }> {
		if (!(await verifyCsrfRequest(config, csrfToken))) return { success: false };
		await performSignOut(config);
		return { success: true };
	};
}

/**
 * Route Handler variant (`export const POST = createSignOutRouteHandler(config)`). Requires the
 * signed CSRF token in the `X-CSRF-Token` header, answers 403 otherwise.
 */
export function createSignOutRouteHandler<TUser>(
	config: ResolvedAuthConfig<TUser>,
): (req: Request) => Promise<Response> {
	return async function POST(req: Request): Promise<Response> {
		if (!(await verifyCsrfRequest(config, req.headers.get("x-csrf-token")))) {
			return Response.json({ success: false, error: "invalid_csrf_token" }, { status: 403 });
		}
		await performSignOut(config);
		return Response.json({ success: true });
	};
}

/** @deprecated Use createSignOutHandler instead. The inline "use server" directive breaks in client component graphs. */
export const createSignOutAction = createSignOutHandler;
