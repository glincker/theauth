import { and, eq } from "drizzle-orm";
import type { Database } from "../db/database.js";
import { agents, delegationChains } from "../db/schema.js";

type ChainRow = typeof delegationChains.$inferSelect;

/** Why a delegator cannot lend authority: its own status or expiry, or an ancestor's. */
export type DelegatorState = "live" | "revoked" | "expired";

const MAX_WALK = 16;

/**
 * A delegator lends authority only while it is live. An agent delegator must be `active` and unexpired. A delegator that is not an agent row (a root user) has no status to check. An agent that itself holds active inbound links is live only if at least one of them traces back to a live delegator, so a revoked or expired agent higher up takes the whole branch below it out, even when no revocation cascade ran. Agents with no inbound links stand on their own.
 */
export function createDelegatorLiveness(db: Database, now: Date) {
	const agentCache = new Map<string, Promise<typeof agents.$inferSelect | undefined>>();
	const inboundCache = new Map<string, Promise<ChainRow[]>>();

	const agentRow = (id: string) => {
		let hit = agentCache.get(id);
		if (!hit) {
			hit = db
				.select()
				.from(agents)
				.where(eq(agents.id, id))
				.limit(1)
				.then((rows) => rows[0]);
			agentCache.set(id, hit);
		}
		return hit;
	};

	const inboundRows = (id: string) => {
		let hit = inboundCache.get(id);
		if (!hit) {
			hit = db
				.select()
				.from(delegationChains)
				.where(and(eq(delegationChains.toAgentId, id), eq(delegationChains.status, "active")))
				.then((rows) => rows.filter((c) => c.expiresAt > now));
			inboundCache.set(id, hit);
		}
		return hit;
	};

	async function stateOf(id: string, trail: Set<string>): Promise<DelegatorState> {
		const row = await agentRow(id);
		if (!row) return "live";
		if (row.status === "expired") return "expired";
		if (row.status !== "active") return "revoked";
		if (row.expiresAt && row.expiresAt <= now) return "expired";
		// A loop has no root authority: fail closed.
		if (trail.has(id) || trail.size >= MAX_WALK) return "revoked";
		const inbound = await inboundRows(id);
		if (inbound.length === 0) return "live";
		const next = new Set(trail).add(id);
		let firstDead: DelegatorState = "revoked";
		for (const [i, link] of inbound.entries()) {
			const state = await stateOf(link.fromAgentId, next);
			if (state === "live") return "live";
			if (i === 0) firstDead = state;
		}
		return firstDead;
	}

	return {
		/** State of the delegator `agentId` as a lender of authority. */
		delegatorState: (agentId: string): Promise<DelegatorState> => stateOf(agentId, new Set()),
		/** Active, unexpired inbound links to `agentId` whose delegator is live. */
		async liveInboundRows(agentId: string): Promise<ChainRow[]> {
			const rows = await inboundRows(agentId);
			const kept: ChainRow[] = [];
			for (const row of rows) {
				if ((await stateOf(row.fromAgentId, new Set([agentId]))) === "live") kept.push(row);
			}
			return kept;
		},
	};
}

/** Active, unexpired inbound links to `agentId` whose delegator is still live. The one filter behind permission merge, lineage and hook chains. */
export async function loadLiveInboundRows(
	db: Database,
	agentId: string,
	now: Date = new Date(),
): Promise<ChainRow[]> {
	return createDelegatorLiveness(db, now).liveInboundRows(agentId);
}
