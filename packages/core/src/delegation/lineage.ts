import { eq } from "drizzle-orm";
import type { Database } from "../db/database.js";
import type { delegationChains } from "../db/schema.js";
import { agents } from "../db/schema.js";
import type { DelegationLink, HookDelegationChain } from "../hooks/lifecycle.js";
import type { Permission } from "../types.js";
import { loadLiveInboundRows } from "./liveness.js";

/** @deprecated Alias kept for compatibility. Use `DelegationLink`. */
export type DelegationHop = DelegationLink;

/** Who stands behind an agent: the root of its delegation chain and every hop. */
export interface DelegationLineage {
	/** The human owning the root agent of the chain (the agent's own owner if not delegated). */
	rootOwnerId?: string;
	/** Agent ids from the root delegator down to the agent. */
	path: string[];
	hops: DelegationLink[];
}

const MAX_WALK = 16;

type ChainRow = typeof delegationChains.$inferSelect;

function toLink(row: ChainRow): DelegationLink {
	return {
		delegationId: row.id,
		fromAgent: row.fromAgentId,
		toAgent: row.toAgentId,
		permissions: (row.permissions as Permission[]).map((p) => ({ ...p })),
		depth: row.depth,
		maxDepth: row.maxDepth,
		expiresAt: row.expiresAt,
		createdAt: row.createdAt,
	};
}

/** Active, unexpired grants whose toAgent is agentId and whose delegator is live (see liveness.ts), oldest first. Same filter as the delegated permission fallback. */
export async function loadInboundGrants(
	db: Database,
	agentId: string,
	now: Date = new Date(),
): Promise<DelegationLink[]> {
	const rows = await loadLiveInboundRows(db, agentId, now);
	return rows.sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime()).map(toLink);
}

/** Walk active, unexpired inbound delegations upward to the root agent. When an agent has several inbound chains the earliest created one is followed, so the result is deterministic. */
export async function resolveLineage(db: Database, agentId: string): Promise<DelegationLineage> {
	const now = new Date();
	const path = [agentId];
	const hops: DelegationLink[] = [];
	const seen = new Set<string>([agentId]);
	let current = agentId;

	for (let i = 0; i < MAX_WALK; i++) {
		const inbound = await loadInboundGrants(db, current, now);
		const next = inbound.find((l) => !seen.has(l.fromAgent));
		if (!next) break;
		hops.unshift(next);
		path.unshift(next.fromAgent);
		seen.add(next.fromAgent);
		current = next.fromAgent;
	}

	const rows = await db
		.select({ ownerId: agents.ownerId })
		.from(agents)
		.where(eq(agents.id, current))
		.limit(1);
	return { rootOwnerId: rows[0]?.ownerId, path, hops };
}

/** Lineage plus every inbound grant of the agent: the shape handed to hooks and explain(). */
export async function resolveHookChain(
	db: Database,
	agentId: string,
): Promise<HookDelegationChain> {
	const lineage = await resolveLineage(db, agentId);
	const inbound = await loadInboundGrants(db, agentId);
	return {
		rootOwnerId: lineage.rootOwnerId,
		path: lineage.path,
		links: lineage.hops,
		inbound,
	};
}
