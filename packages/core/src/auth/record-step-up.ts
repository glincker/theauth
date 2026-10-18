import { extractToken } from "../plugin/helpers.js";
import type { PluginContext } from "../plugin/types.js";
import type { AuthMethod } from "../session/auth-context.js";

/**
 * Record a re-authentication on the session that made `request`, after the proof was verified.
 * This is how a signed-in user steps up (RFC 9470): proving a TOTP code or passkey again refreshes the
 * session's `authTime` and can raise its `acr`. A request without a valid session, or a deployment
 * without a session manager, records nothing and returns false. Errors count as "not recorded", never
 * as a failed verification.
 */
export async function recordStepUp(
	ctx: Pick<PluginContext, "sessionManager" | "config">,
	request: Request,
	method: AuthMethod,
): Promise<boolean> {
	const sessions = ctx.sessionManager;
	if (!sessions) return false;
	try {
		const token = extractToken(request, ctx.config.auth?.session?.cookieName);
		if (!token) return false;
		const session = await sessions.validate(token);
		if (!session) return false;
		return (await sessions.recordAuth(session.id, method)) !== null;
	} catch {
		return false;
	}
}
