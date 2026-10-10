import type { createTheAuth } from "@glinr/theauth";
import { agents, auditLogs, permissions, users } from "@glinr/theauth";
import { count, eq, inArray, lt } from "drizzle-orm";

export type DemoAuth = Awaited<ReturnType<typeof createTheAuth>>;

/** The one owner row every demo agent hangs off. It holds no personal data. */
export const OWNER_ID = "demo-owner";
const OWNER_EMAIL = "demo-owner@example.invalid";

// D1 caps bound parameters per statement, so large IN lists are chunked.
const CHUNK = 50;

export async function ensureOwner(auth: DemoAuth): Promise<void> {
	const now = new Date();
	await auth.db
		.insert(users)
		.values({
			id: OWNER_ID,
			email: OWNER_EMAIL,
			name: "Shared demo owner",
			createdAt: now,
			updatedAt: now,
		})
		.onConflictDoNothing();
}

export async function countAgents(auth: DemoAuth): Promise<number> {
	const rows = await auth.db.select({ n: count() }).from(agents);
	return rows[0]?.n ?? 0;
}

/**
 * Agents held by one client. The client is a keyed fingerprint stored in the
 * agent's metadata, never the raw IP.
 */
export async function countAgentsForClient(auth: DemoAuth, clientKey: string): Promise<number> {
	const rows = await auth.db.select({ metadata: agents.metadata }).from(agents);
	return rows.filter((r) => r.metadata?.client === clientKey).length;
}

export async function countAuditRows(auth: DemoAuth, agentId: string): Promise<number> {
	const rows = await auth.db
		.select({ n: count() })
		.from(auditLogs)
		.where(eq(auditLogs.agentId, agentId));
	return rows[0]?.n ?? 0;
}

/**
 * Delete agents (and their permissions and audit rows) created before the
 * cutoff. Returns the number of agents removed.
 */
export async function cleanupExpired(auth: DemoAuth, olderThan: Date): Promise<number> {
	const stale = await auth.db
		.select({ id: agents.id })
		.from(agents)
		.where(lt(agents.createdAt, olderThan));
	const ids = stale.map((r) => r.id);
	for (let i = 0; i < ids.length; i += CHUNK) {
		const batch = ids.slice(i, i + CHUNK);
		await auth.db.delete(auditLogs).where(inArray(auditLogs.agentId, batch));
		await auth.db.delete(permissions).where(inArray(permissions.agentId, batch));
		await auth.db.delete(agents).where(inArray(agents.id, batch));
	}
	return ids.length;
}

/** Keyed SHA-256 of the client IP and the UTC day. The key rotates with the day. */
export async function clientFingerprint(
	ip: string,
	salt: string,
	now: Date = new Date(),
): Promise<string> {
	const day = now.toISOString().slice(0, 10);
	const bytes = new TextEncoder().encode(`${salt}|${day}|${ip}`);
	const digest = await crypto.subtle.digest("SHA-256", bytes);
	return Array.from(new Uint8Array(digest))
		.slice(0, 12)
		.map((b) => b.toString(16).padStart(2, "0"))
		.join("");
}
