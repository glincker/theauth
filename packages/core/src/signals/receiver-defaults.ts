/** Default receiver behavior: end local sessions when the transmitter says the session, all sessions, or the account is gone. */

import { eq } from "drizzle-orm";
import type { Database } from "../db/database.js";
import { users } from "../db/schema.js";
import type { SessionManager } from "../session/session.js";
import type { EventHandler, ReceivedEvent } from "./receiver.js";
import type { SimpleSubject, SubjectIdentifier } from "./types.js";
import { CAEP_SESSION_REVOKED, RISC_ACCOUNT_DISABLED, RISC_SESSIONS_REVOKED } from "./types.js";

export interface DefaultHandlersOptions {
	sessionManager: Pick<SessionManager, "revoke" | "revokeAll">;
	/** Issuer of the transmitter. `iss_sub` subjects from it map `sub` to a local user id. */
	issuer: string;
	/** Look up users by email. Pass `db` for the built-in lookup. */
	db?: Database;
	/**
	 * Map a subject to a local user id. Overrides the default mapping: `iss_sub` from `issuer` is the user id, `email` is looked up in the user table, `opaque` is taken as the user id. Return null when unknown.
	 */
	resolveUserId?: (subject: SimpleSubject) => Promise<string | null>;
	/** Called after sessions were revoked. */
	onRevoked?: (info: { userId: string; type: string }) => Promise<void> | void;
}

function userSubject(subject: SubjectIdentifier): SimpleSubject | null {
	if (subject.format === "complex") return subject.user ?? null;
	return subject;
}

export function createDefaultHandlers(opts: DefaultHandlersOptions): Record<string, EventHandler> {
	async function resolve(subject: SimpleSubject): Promise<string | null> {
		if (opts.resolveUserId) return opts.resolveUserId(subject);
		switch (subject.format) {
			case "iss_sub":
				return subject.iss === opts.issuer ? subject.sub : null;
			case "email": {
				if (!opts.db) return null;
				const rows = await opts.db
					.select({ id: users.id })
					.from(users)
					.where(eq(users.email, subject.email.toLowerCase()))
					.limit(1);
				return rows[0]?.id ?? null;
			}
			case "opaque":
				return subject.id;
		}
	}

	const revokeUser: EventHandler = async (event: ReceivedEvent) => {
		if (!event.subject) return;
		const subject = userSubject(event.subject);
		if (!subject) return;
		const userId = await resolve(subject);
		if (!userId) return;
		await opts.sessionManager.revokeAll(userId);
		await opts.onRevoked?.({ userId, type: event.type });
	};

	const sessionRevoked: EventHandler = async (event) => {
		const subject = event.subject;
		// A subject naming one session revokes just that session.
		if (subject?.format === "complex" && subject.session?.format === "opaque") {
			await opts.sessionManager.revoke(subject.session.id);
			return;
		}
		await revokeUser(event);
	};

	return {
		[CAEP_SESSION_REVOKED]: sessionRevoked,
		[RISC_SESSIONS_REVOKED]: revokeUser,
		[RISC_ACCOUNT_DISABLED]: revokeUser,
	};
}
