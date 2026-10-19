/**
 * Progress marker for a resumable `deleteUser`. The marker lives in the metadata of the tombstone user (keyed by the stable anonymous id), so it needs no table of its own and survives the deletion of the real user row. Each step of the erasure is safe to rerun, the marker only says which steps a retry can skip. A stale or regressed marker (two concurrent calls) makes a retry redo steps, never skip one that did not run.
 */
import { eq } from "drizzle-orm";
import type { Database } from "../db/database.js";
import { users } from "../db/schema.js";

export const ERASURE_MARKER_KEY = "theauthErasure";

export interface ErasureCounts {
	deletedSessions: number;
	deletedDelegations: number;
	deletedApiKeys: number;
	anonymizedAuditLogs: number;
}

export interface ErasureMarker {
	v: 1;
	/** Number of steps finished, in order. */
	completed: number;
	done: boolean;
	/** Agents the user owned when the erasure began. Ids only, dropped once the erasure is done. */
	agentIds: string[];
	keepAuditLogs: boolean;
	deleteOrganizations: boolean;
	deletedAgents: number;
	counts: ErasureCounts;
}

function isMarker(value: unknown): value is ErasureMarker {
	if (typeof value !== "object" || value === null) return false;
	const m = value as Partial<ErasureMarker>;
	return (
		m.v === 1 &&
		typeof m.completed === "number" &&
		typeof m.done === "boolean" &&
		Array.isArray(m.agentIds) &&
		typeof m.counts === "object"
	);
}

export async function readErasureMarker(
	db: Database,
	anonUserId: string,
): Promise<ErasureMarker | null> {
	const rows = await db
		.select({ metadata: users.metadata })
		.from(users)
		.where(eq(users.id, anonUserId));
	const marker = (rows[0]?.metadata as Record<string, unknown> | null | undefined)?.[
		ERASURE_MARKER_KEY
	];
	return isMarker(marker) ? marker : null;
}

/** Writes the marker unless a later state is already stored, so a slow concurrent call cannot move it backwards. */
export async function saveErasureMarker(
	db: Database,
	anonUserId: string,
	marker: ErasureMarker,
	force = false,
): Promise<void> {
	const current = force ? null : await readErasureMarker(db, anonUserId);
	if (current && !marker.done && (current.done || current.completed > marker.completed)) return;
	await db
		.update(users)
		.set({ metadata: { [ERASURE_MARKER_KEY]: marker } })
		.where(eq(users.id, anonUserId));
}
