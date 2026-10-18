import { eq } from "drizzle-orm";
import { recordAuditEvent } from "../audit/record.js";
import { generateId } from "../crypto/web-crypto.js";
import type { Database } from "../db/database.js";
import { agents, users } from "../db/schema.js";
import { toStoreConflict } from "../db/store-conflict.js";

/** Thrown when a banned user tries to start a session. The message is the same for every ban, so it reveals nothing about the account. */
export class UserBannedError extends Error {
	readonly code = "USER_BANNED";
	constructor() {
		super("Sign-in is not available for this account.");
		this.name = "UserBannedError";
	}
}

/** Id of the inert agent that carries sign-in audit rows for one user (audit rows need an agent). */
function signInAuditAgentId(userId: string): string {
	return `signin:${userId}`;
}

async function ensureSignInAuditAgent(db: Database, userId: string): Promise<string> {
	const id = signInAuditAgentId(userId);
	const found = await db.select({ id: agents.id }).from(agents).where(eq(agents.id, id)).limit(1);
	if (found.length > 0) return id;
	const now = new Date();
	try {
		await db.insert(agents).values({
			id,
			ownerId: userId,
			name: "[sign-in audit]",
			type: "service",
			status: "revoked",
			// Not a hex digest, so no presented token can ever hash to it.
			tokenHash: `system:${generateId()}`,
			tokenPrefix: "system",
			expiresAt: new Date(0),
			metadata: {},
			createdAt: now,
			updatedAt: now,
		});
	} catch (error) {
		if (!toStoreConflict(error, "agents")) throw error;
	}
	return id;
}

async function auditBannedSignIn(db: Database, userId: string): Promise<void> {
	try {
		const agentId = await ensureSignInAuditAgent(db, userId);
		await recordAuditEvent(db, {
			agentId,
			userId,
			action: "sign_in",
			resource: `user:${userId}`,
			result: "denied",
			reason: "user_banned",
			durationMs: 0,
		});
	} catch {
		// Best effort: the refusal stands even when the audit write fails.
	}
}

/** True when the user is banned right now (an expired ban no longer counts). A user with no row is not banned. Writes a denied `sign_in` audit row when it returns true. */
export async function refuseBannedUser(db: Database, userId: string): Promise<boolean> {
	const rows = await db
		.select({ banned: users.banned, banExpiresAt: users.banExpiresAt })
		.from(users)
		.where(eq(users.id, userId))
		.limit(1);
	const row = rows[0];
	if (!row || Number(row.banned) !== 1) return false;
	if (row.banExpiresAt && row.banExpiresAt.getTime() <= Date.now()) return false;
	await auditBannedSignIn(db, userId);
	return true;
}

/** Throws {@link UserBannedError} (generic message, audit row) when the user is banned. */
export async function assertUserNotBanned(db: Database, userId: string): Promise<void> {
	if (await refuseBannedUser(db, userId)) throw new UserBannedError();
}

/** Wraps a `resolveUserId` callback so a banned user resolves to null (login required) with an audit row. For `createMcpModule`. */
export function bannedAwareResolveUserId(
	db: Database,
	resolve: (request: Request) => Promise<string | null>,
): (request: Request) => Promise<string | null> {
	return async (request) => {
		const userId = await resolve(request);
		if (userId && (await refuseBannedUser(db, userId))) return null;
		return userId;
	};
}
