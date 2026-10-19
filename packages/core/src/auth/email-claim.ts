/**
 * Mailbox proof for an existing account.
 *
 * A magic link or an email code proves the caller controls the mailbox. When the
 * account row already existed with an unverified address, someone else may have
 * registered it first (account pre-hijacking): they know the password, or have a
 * login through a weak provider, or hold an open session. Claiming the account
 * for the real owner means removing everything the squatter could have planted
 * before the address was proven.
 */

import { eq } from "drizzle-orm";
import type { Database } from "../db/database.js";
import { passkeyCredentials, sessions, usernameAccounts, users } from "../db/schema.js";
import { oauthAccounts } from "./oauth/schema.js";

export interface ClaimOptions {
	/**
	 * Keep passwords, linked providers, passkeys and sessions that exist on an
	 * unverified account when its owner first proves the mailbox. Default false.
	 * Only set this when every sign-up path of your app verifies the address
	 * before it creates credentials.
	 */
	keepUnverifiedCredentials?: boolean;
}

/** True for the "table was never created" error of any dialect, which means the feature is off. */
function isMissingTable(error: unknown): boolean {
	for (let e: unknown = error, depth = 0; e && depth < 4; depth++) {
		const err = e as { message?: unknown; code?: unknown; errno?: unknown; cause?: unknown };
		const message = typeof err.message === "string" ? err.message : "";
		if (
			/no such table/i.test(message) ||
			/relation ".*" does not exist/i.test(message) ||
			/table '.*' doesn't exist/i.test(message) ||
			err.code === "42P01" ||
			err.code === "ER_NO_SUCH_TABLE" ||
			err.errno === 1146
		) {
			return true;
		}
		e = err.cause;
	}
	return false;
}

/** Run one credential delete. A feature whose table does not exist has nothing to clear, anything else still throws. */
async function clearIfPresent(run: () => Promise<unknown>): Promise<void> {
	try {
		await run();
	} catch (error) {
		if (!isMissingTable(error)) throw error;
	}
}

/** Mark the address verified. On a first proof, also drop credentials made before it. */
export async function claimVerifiedMailbox(
	db: Database,
	userId: string,
	options: ClaimOptions = {},
	revokeSessions?: (userId: string) => Promise<unknown>,
): Promise<void> {
	const row = (
		await db.select({ emailVerified: users.emailVerified }).from(users).where(eq(users.id, userId))
	)[0];
	if (!row || row.emailVerified === 1) return;

	if (!options.keepUnverifiedCredentials) {
		await clearIfPresent(() =>
			db.delete(usernameAccounts).where(eq(usernameAccounts.userId, userId)),
		);
		await clearIfPresent(() => db.delete(oauthAccounts).where(eq(oauthAccounts.userId, userId)));
		await clearIfPresent(() =>
			db.delete(passkeyCredentials).where(eq(passkeyCredentials.userId, userId)),
		);
		await db.delete(sessions).where(eq(sessions.userId, userId));
		// The session manager may hold a cache the row delete does not reach.
		await revokeSessions?.(userId);
	}
	await db
		.update(users)
		.set({ emailVerified: 1, updatedAt: new Date() })
		.where(eq(users.id, userId));
}
