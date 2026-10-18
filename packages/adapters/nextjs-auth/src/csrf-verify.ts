import "server-only";

import { getConfigSecret } from "./config.js";
import { getCsrfToken, getSessionToken } from "./cookies.js";
import { csrfValuesEqual, verifyCsrfToken } from "./csrf.js";
import type { ResolvedAuthConfig } from "./types.js";

/**
 * Verifies a signed double-submit CSRF pair for the current request: the submitted value (header
 * or action argument) must equal the CSRF cookie, and carry a valid signature bound to the
 * current session token. Fails closed on any missing piece. Use it in every state changing route
 * handler or server action you add.
 */
export async function verifyCsrfRequest<TUser>(
	config: ResolvedAuthConfig<TUser>,
	submitted: string | null | undefined,
): Promise<boolean> {
	const secret = getConfigSecret(config);
	if (!secret || !submitted) return false;
	const [cookie, sessionToken] = await Promise.all([getCsrfToken(config), getSessionToken(config)]);
	if (!cookie || !sessionToken) return false;
	if (!csrfValuesEqual(submitted, cookie)) return false;
	return verifyCsrfToken(secret, sessionToken, submitted);
}
