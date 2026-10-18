import { eq } from "drizzle-orm";
import type { Database } from "../db/database.js";
import { agents } from "../db/schema.js";
import type { RevocationBus } from "../mcp/revocation-bus.js";
import { revocationRowExpiry } from "../mcp/revocation-bus.js";

/** An agent whose authority was ended together with its owner. */
export interface RevokedOwnedAgent {
	id: string;
	expiresAt: Date | null;
}

/** Marks every agent owned by `userId` revoked and returns them, so their `agent` rows can be pushed. */
export async function revokeOwnedAgents(
	db: Database,
	userId: string,
): Promise<RevokedOwnedAgent[]> {
	const owned = await db
		.select({ id: agents.id, expiresAt: agents.expiresAt })
		.from(agents)
		.where(eq(agents.ownerId, userId));
	if (owned.length === 0) return [];
	await db
		.update(agents)
		.set({ status: "revoked", updatedAt: new Date() })
		.where(eq(agents.ownerId, userId));
	return owned.map((a) => ({ id: a.id, expiresAt: a.expiresAt ?? null }));
}

/**
 * Pushes a `sub` watermark for the user and an `agent` row per owned agent through the shared revocation bus, so MCP access and refresh tokens die on every instance.
 * Never throws: the bus reports its own failures and the database change is already made.
 * The `sub` row is a watermark (tokens issued at or before it die), so a later unban does not bring old tokens back.
 */
export async function publishUserRevocation(
	bus: RevocationBus | null | undefined,
	userId: string,
	ownedAgents: RevokedOwnedAgent[],
	reason: string,
): Promise<void> {
	if (!bus) return;
	const now = new Date();
	try {
		await bus.publish({ kind: "sub", ids: [userId], revokedAt: now, reason, userId }, [
			{ kind: "sub", id: userId, expiresAt: revocationRowExpiry(undefined, now), reason },
		]);
	} catch {
		// The bus reports its own failures.
	}
	if (ownedAgents.length === 0) return;
	try {
		await bus.publish(
			{
				kind: "agent",
				ids: ownedAgents.map((a) => a.id),
				revokedAt: now,
				reason,
				userId,
				sourceId: userId,
			},
			ownedAgents.map((a) => ({
				kind: "agent" as const,
				id: a.id,
				expiresAt: revocationRowExpiry(a.expiresAt, now),
				reason,
				sourceId: userId,
			})),
		);
	} catch {
		// The bus reports its own failures.
	}
}

/** Revokes the user's agents and pushes every MCP revocation row for the user. */
export async function revokeUserMcpAccess(
	db: Database,
	bus: RevocationBus | null | undefined,
	userId: string,
	reason: string,
): Promise<void> {
	const owned = await revokeOwnedAgents(db, userId);
	await publishUserRevocation(bus, userId, owned, reason);
}
