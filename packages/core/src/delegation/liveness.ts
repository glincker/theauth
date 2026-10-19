import { eq } from "drizzle-orm";
import type { Database } from "../db/database.js";
import { agents, delegationChains, permissions } from "../db/schema.js";
import type { ResourceMatching } from "../policy/resource-match.js";
import type { Permission } from "../types.js";
import { isPermissionSubset } from "./subset.js";

type ChainRow = typeof delegationChains.$inferSelect;

/** Why a delegator cannot lend authority: its own status or expiry, or an ancestor's. */
export type DelegatorState = "live" | "revoked" | "expired";

const MAX_WALK = 16;

/**
 * A delegator lends authority only while it is live. An agent delegator must be `active` and unexpired. A delegator that is not an agent row (a root user) has no status to check. An agent that itself holds active inbound links is live only if at least one of them traces back to a live delegator, so a revoked or expired agent higher up takes the whole branch below it out, even when no revocation cascade ran. The exception is a link whose permissions the active delegator holds directly: that authority did not come through the dead chain, so the link stays. Agents that never had inbound links stand on their own. An agent whose inbound links are all revoked or expired does not: it lends only what its own permissions cover.
 */
export function createDelegatorLiveness(
	db: Database,
	now: Date,
	matching: ResourceMatching = "colon",
) {
	const agentCache = new Map<string, Promise<typeof agents.$inferSelect | undefined>>();
	const ownCache = new Map<string, Promise<Permission[]>>();

	const ownPermissions = (id: string) => {
		let hit = ownCache.get(id);
		if (!hit) {
			hit = db
				.select()
				.from(permissions)
				.where(eq(permissions.agentId, id))
				.then((rows) => rows.map((r) => ({ resource: r.resource, actions: r.actions })));
			ownCache.set(id, hit);
		}
		return hit;
	};

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

	// One read per agent covers both questions: the active unexpired links (authority now) and every link ever
	// received (was this agent fed by a chain that has since died). Two queries on the same rows would also let a
	// concurrent revoke show up in one answer and not the other.
	const allInboundCache = new Map<string, Promise<ChainRow[]>>();
	const anyInboundRows = (id: string) => {
		let hit = allInboundCache.get(id);
		if (!hit) {
			hit = db
				.select()
				.from(delegationChains)
				.where(eq(delegationChains.toAgentId, id))
				.then((rows) => rows);
			allInboundCache.set(id, hit);
		}
		return hit;
	};

	const inboundCache = new Map<string, Promise<ChainRow[]>>();
	const inboundRows = (id: string) => {
		let hit = inboundCache.get(id);
		if (!hit) {
			hit = anyInboundRows(id).then((rows) =>
				rows.filter((c) => c.status === "active" && c.expiresAt > now),
			);
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
		if (inbound.length === 0) {
			// Links that once fed this agent are all revoked or expired: whatever it lends came through them, so it is no longer self-standing (own permissions are handled per link in stateOfLink).
			const past = await anyInboundRows(id);
			if (past.length === 0) return "live";
			return past.some((c) => c.status === "revoked") ? "revoked" : "expired";
		}
		const next = new Set(trail).add(id);
		let firstDead: DelegatorState = "revoked";
		for (const [i, link] of inbound.entries()) {
			const state = await stateOfLink(link, next);
			if (state === "live") return "live";
			if (i === 0) firstDead = state;
		}
		return firstDead;
	}

	/** A link is live if its delegator is live, or if the delegator is itself active and unexpired and its own direct permissions cover what the link grants (that authority never came through an inbound chain). */
	async function stateOfLink(link: ChainRow, trail: Set<string>): Promise<DelegatorState> {
		const state = await stateOf(link.fromAgentId, trail);
		if (state === "live") return "live";
		const row = await agentRow(link.fromAgentId);
		if (!row || row.status !== "active" || (row.expiresAt && row.expiresAt <= now)) return state;
		const own = await ownPermissions(link.fromAgentId);
		return isPermissionSubset(own, link.permissions as Permission[], matching) ? "live" : state;
	}

	return {
		/** State of a link as a carrier of authority: its delegator's state, with the direct permission exception. Does not read the link's own status or expiry; callers filter those first. */
		linkState: (link: ChainRow): Promise<DelegatorState> =>
			stateOfLink(link, new Set([link.toAgentId])),
		/** State of the delegator `agentId` as a lender of authority. */
		delegatorState: (agentId: string): Promise<DelegatorState> => stateOf(agentId, new Set()),
		/** Active, unexpired inbound links to `agentId` whose delegator is live. */
		async liveInboundRows(agentId: string): Promise<ChainRow[]> {
			const rows = await inboundRows(agentId);
			const kept: ChainRow[] = [];
			for (const row of rows) {
				if ((await stateOfLink(row, new Set([agentId]))) === "live") kept.push(row);
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
	matching: ResourceMatching = "colon",
): Promise<ChainRow[]> {
	return createDelegatorLiveness(db, now, matching).liveInboundRows(agentId);
}

/** State of one delegation link as a carrier of authority (see {@link createDelegatorLiveness}). The link's own status and expiry are the caller's to check. */
export async function linkState(
	db: Database,
	link: ChainRow,
	now: Date = new Date(),
): Promise<DelegatorState> {
	return createDelegatorLiveness(db, now).linkState(link);
}
