import { and, eq } from "drizzle-orm";
import type { Database } from "../db/database.js";
import { agents, delegationChains } from "../db/schema.js";

export interface DelegationHop {
	delegationId: string;
	fromAgent: string;
	toAgent: string;
}

/** Who stands behind an agent: the root of its delegation chain and every hop. */
export interface DelegationLineage {
	/** The human owning the root agent of the chain (the agent's own owner if not delegated). */
	rootOwnerId?: string;
	/** Agent ids from the root delegator down to the agent. */
	path: string[];
	hops: DelegationHop[];
}

const MAX_WALK = 16;

/**
 * Walk active, unexpired inbound delegations upward to the root agent. When an
 * agent has several inbound chains the earliest created one is followed, so the
 * result is deterministic.
 */
export async function resolveLineage(db: Database, agentId: string): Promise<DelegationLineage> {
	const now = new Date();
	const path = [agentId];
	const hops: DelegationHop[] = [];
	const seen = new Set<string>([agentId]);
	let current = agentId;

	for (let i = 0; i < MAX_WALK; i++) {
		const inbound = await db
			.select()
			.from(delegationChains)
			.where(and(eq(delegationChains.toAgentId, current), eq(delegationChains.status, "active")));
		const live = inbound
			.filter((c) => c.expiresAt > now && !seen.has(c.fromAgentId))
			.sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime());
		const next = live[0];
		if (!next) break;
		hops.unshift({ delegationId: next.id, fromAgent: next.fromAgentId, toAgent: next.toAgentId });
		path.unshift(next.fromAgentId);
		seen.add(next.fromAgentId);
		current = next.fromAgentId;
	}

	const rows = await db
		.select({ ownerId: agents.ownerId })
		.from(agents)
		.where(eq(agents.id, current))
		.limit(1);
	return { rootOwnerId: rows[0]?.ownerId, path, hops };
}
