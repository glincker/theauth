import { extractToken } from "../plugin/helpers.js";
import type { PluginContext } from "../plugin/types.js";
import type { AuthMethod } from "../session/auth-context.js";
import type { SessionManager } from "../session/session.js";

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
	expectedUserId?: string,
): Promise<boolean> {
	return recordStepUpOnSession(
		ctx.sessionManager,
		ctx.config.auth?.session?.cookieName,
		request,
		method,
		expectedUserId,
	);
}

/**
 * Same as {@link recordStepUp} for callers that hold the session manager directly. With
 * `expectedUserId` the session must belong to that user, so a proof made by one person can never
 * raise the authentication level of another person's session.
 */
export async function recordStepUpOnSession(
	sessions: SessionManager | null,
	cookieName: string | undefined,
	request: Request,
	method: AuthMethod,
	expectedUserId?: string,
): Promise<boolean> {
	if (!sessions) return false;
	try {
		const token = extractToken(request, cookieName ?? sessions.cookieName);
		if (!token) return false;
		const session = await sessions.validate(token);
		if (!session) return false;
		if (expectedUserId !== undefined && session.userId !== expectedUserId) return false;
		return (await sessions.recordAuth(session.id, method)) !== null;
	} catch {
		return false;
	}
}
