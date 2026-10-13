/**
 * Default session revocation for the back-channel logout receiver.
 *
 * A logout token names a `sub` and/or a `sid`. This maps them to local
 * sessions and revokes them through the session manager.
 *
 * - `sub` only: every session of the mapped user.
 * - `sub` + `sid`: sessions of that user whose metadata `sid` matches.
 * - `sid` only: needs `findSessionsBySid`, because sessions are indexed by
 *   user. Without it the receiver answers 400 so the IdP knows it was not done.
 *
 * Record the IdP `sid` on the local session at login time:
 * `sessionManager.create(userId, { sid })`.
 */

import type { Session, SessionManager } from "../session/session.js";
import type { LogoutTokenClaims } from "./federated-logout.js";

export interface SessionRevokerOptions {
	/** Local session manager. Defaults: `list` and `revoke` are used. */
	sessionManager: Pick<SessionManager, "list" | "revoke">;
	/**
	 * Map the IdP `sub` to a local user id. Default: the `sub` is the local
	 * user id. Return null when the user is unknown (nothing to revoke).
	 */
	resolveUserId?: (claims: LogoutTokenClaims) => Promise<string | null>;
	/** Find local sessions by IdP `sid` when no `sub` is present. */
	findSessionsBySid?: (sid: string) => Promise<Session[]>;
	/** Metadata key that stores the IdP sid. Default `sid`. */
	sidMetadataKey?: string;
}

export type SessionRevoker = (claims: LogoutTokenClaims) => Promise<{ revoked: number }>;

export function createSessionRevoker(options: SessionRevokerOptions): SessionRevoker {
	const key = options.sidMetadataKey ?? "sid";

	return async (claims) => {
		let targets: Session[];

		if (claims.sub) {
			const userId = options.resolveUserId ? await options.resolveUserId(claims) : claims.sub;
			if (!userId) return { revoked: 0 };
			const sessions = await options.sessionManager.list(userId);
			targets = claims.sid ? sessions.filter((s) => s.metadata?.[key] === claims.sid) : sessions;
		} else if (claims.sid) {
			if (!options.findSessionsBySid) {
				throw new Error("sid-only logout needs findSessionsBySid");
			}
			targets = await options.findSessionsBySid(claims.sid);
		} else {
			return { revoked: 0 };
		}

		let revoked = 0;
		for (const session of targets) {
			await options.sessionManager.revoke(session.id);
			revoked += 1;
		}
		return { revoked };
	};
}
