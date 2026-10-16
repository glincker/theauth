import { and, eq } from "drizzle-orm";
import type { Database } from "../db/database.js";
import { delegationChains } from "../db/schema.js";
import type { McpDelegationHop, McpDelegationLink, McpDelegationStore } from "./types.js";

/** Why a delegation chain failed the live check. */
export interface McpDelegationFailure {
	from: string;
	to: string;
	reason: "missing" | "revoked" | "expired";
}

/**
 * Walk the delegation chain from a token against live link records.
 *
 * `hops` is the `act` claim flattened current actor first. The authority path
 * runs from the token subject through the innermost actor out to the current
 * actor, so each consecutive pair must have an active, unexpired link. Returns
 * the first failing link, or null when every link is live (or there are no hops).
 */
export async function checkLiveDelegation(
	store: McpDelegationStore,
	subject: string,
	hops: McpDelegationHop[],
	now: Date = new Date(),
): Promise<McpDelegationFailure | null> {
	const path = [subject, ...hops.map((h) => h.sub).reverse()];
	for (let i = 0; i < path.length - 1; i++) {
		const from = path[i] as string;
		const to = path[i + 1] as string;
		const link = await store.findLink(from, to);
		if (!link) return { from, to, reason: "missing" };
		if (link.status === "revoked") return { from, to, reason: "revoked" };
		if (link.status === "expired" || link.expiresAt <= now) return { from, to, reason: "expired" };
	}
	return null;
}

/**
 * Delegation store backed by the `delegation_chains` table, where the chain
 * source and target ids are the `act` subjects (agent ids). When several rows
 * link the same pair, a live one wins so a newer grant is not masked by an old
 * revoked row.
 */
export function createDbDelegationStore(db: Database): McpDelegationStore {
	return {
		async findLink(from, to): Promise<McpDelegationLink | null> {
			const rows = await db
				.select()
				.from(delegationChains)
				.where(and(eq(delegationChains.fromAgentId, from), eq(delegationChains.toAgentId, to)));
			const now = new Date();
			const live = rows.find((r) => r.status === "active" && r.expiresAt > now);
			const row = live ?? rows[0];
			return row ? { status: row.status, expiresAt: row.expiresAt } : null;
		},
	};
}
