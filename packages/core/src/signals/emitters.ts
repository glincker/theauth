/**
 * Opt-in bridges from existing TheAuth security paths to SSF events.
 *
 * Nothing is emitted unless you pass one of these callbacks into the matching
 * config (`session.onRevoke`, `admin.onAdminAction`, `passwordReset.onPasswordChanged`,
 * `totp.onChange`, `passkey.onCredentialChange`). Failures are swallowed so a
 * receiver outage never blocks a sign-out or password change.
 */

import type { AdminAuditEntry } from "../auth/admin.js";
import type { Session } from "../session/session.js";
import type { BuiltEvent } from "./events.js";
import { events } from "./events.js";
import type { SubjectIdentifier } from "./types.js";

export type EmitFn = (input: {
	type: string;
	payload?: Record<string, unknown>;
	subject: SubjectIdentifier;
}) => Promise<unknown>;

export interface EmissionBridgeOptions {
	emit: EmitFn;
	/** Subject for a local user. Default `iss_sub` with `issuer` and the user id. */
	subjectForUser?: (userId: string) => SubjectIdentifier | Promise<SubjectIdentifier>;
	/** Needed for the default subject mapping. */
	issuer: string;
}

export interface EmissionBridge {
	/** For `session.onRevoke`. One session-revoked per revoked session. */
	onSessionsRevoked: (revoked: Session[]) => Promise<void>;
	/** For `admin.onAdminAction`. `ban_user` and `unban_user` become account-disabled and account-enabled. */
	onAdminAction: (entry: AdminAuditEntry) => Promise<void>;
	/** For `passwordReset.onPasswordChanged`. */
	onPasswordChanged: (userId: string) => Promise<void>;
	/** For `totp.onChange`. */
	onTotpChange: (userId: string, change: "enabled" | "disabled") => Promise<void>;
	/** For `passkey.onCredentialChange`. */
	onPasskeyChange: (userId: string, change: "added" | "removed") => Promise<void>;
}

export function createEmissionBridge(options: EmissionBridgeOptions): EmissionBridge {
	const subjectFor = async (userId: string): Promise<SubjectIdentifier> =>
		options.subjectForUser
			? options.subjectForUser(userId)
			: { format: "iss_sub", iss: options.issuer, sub: userId };

	async function send(event: BuiltEvent, subject: SubjectIdentifier): Promise<void> {
		try {
			await options.emit({ type: event.type, payload: event.payload, subject });
		} catch {
			// Signal delivery must never break the path that produced it.
		}
	}

	return {
		async onSessionsRevoked(revoked) {
			for (const session of revoked) {
				try {
					const user = await subjectFor(session.userId);
					if (user.format === "complex") continue;
					await send(events.sessionRevoked(), {
						format: "complex",
						user,
						session: { format: "opaque", id: session.id },
					});
				} catch {
					// See above.
				}
			}
		},

		async onAdminAction(entry) {
			try {
				const subject = await subjectFor(entry.targetUserId);
				if (entry.action === "ban_user") {
					await send(events.accountDisabled(), subject);
					await send(events.sessionsRevoked(), subject);
				} else if (entry.action === "unban_user") {
					await send(events.accountEnabled(), subject);
				}
			} catch {
				// See above.
			}
		},

		async onPasswordChanged(userId) {
			try {
				await send(
					events.credentialChange({ credentialType: "password", changeType: "update" }),
					await subjectFor(userId),
				);
			} catch {
				// See above.
			}
		},

		async onTotpChange(userId, change) {
			try {
				await send(
					events.credentialChange({
						credentialType: "app",
						changeType: change === "enabled" ? "create" : "delete",
					}),
					await subjectFor(userId),
				);
			} catch {
				// See above.
			}
		},

		async onPasskeyChange(userId, change) {
			try {
				await send(
					events.credentialChange({
						credentialType: "fido2-roaming",
						changeType: change === "added" ? "create" : "delete",
					}),
					await subjectFor(userId),
				);
			} catch {
				// See above.
			}
		},
	};
}
