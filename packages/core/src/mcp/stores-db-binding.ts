import { and, asc, eq, inArray } from "drizzle-orm";
import type { Database } from "../db/database.js";
import { agents, delegationChains } from "../db/schema.js";
import { createDelegatorLiveness } from "../delegation/liveness.js";
import { MCP_BINDING_NO_EXPIRY } from "./binding.js";
import type {
	McpBindingAgent,
	McpBindingStore,
	McpBindingVerdict,
	McpDelegationBinding,
	McpLiveLink,
} from "./revocation-types.js";
import { MCP_DELEGATION_BINDING_VERSION } from "./revocation-types.js";

function wellFormed(binding: McpDelegationBinding): boolean {
	return (
		binding.v === MCP_DELEGATION_BINDING_VERSION &&
		Array.isArray(binding.agt) &&
		Array.isArray(binding.lnk) &&
		binding.agt.length >= 1 &&
		binding.lnk.length === binding.agt.length - 1 &&
		binding.agt.every((id) => typeof id === "string" && id.length > 0) &&
		binding.lnk.every((id) => typeof id === "string" && id.length > 0)
	);
}

function earlier(a: Date, b: Date | null): Date {
	return b !== null && b.getTime() < a.getTime() ? b : a;
}

/**
 * Delegation binding store over the TheAuth database (`theauth_delegation_chains`, `theauth_agents`).
 * Every read is by primary key (`id IN`) or by the `(from_agent_id, status)` and `(to_agent_id, status)`
 * indexes that migration 0007 adds. Store errors propagate: callers fail closed.
 */
export function createDbBindingStore(db: Database): McpBindingStore {
	async function agentRows(ids: string[]): Promise<Map<string, McpBindingAgent>> {
		const unique = [...new Set(ids)];
		const out = new Map<string, McpBindingAgent>();
		if (unique.length === 0) return out;
		const rows = await db
			.select({
				id: agents.id,
				status: agents.status,
				expiresAt: agents.expiresAt,
				ownerId: agents.ownerId,
			})
			.from(agents)
			.where(inArray(agents.id, unique));
		for (const r of rows) {
			out.set(r.id, { status: r.status, expiresAt: r.expiresAt ?? null, ownerId: r.ownerId });
		}
		return out;
	}

	return {
		agents: agentRows,

		async findLiveLink(from, to, now): Promise<McpLiveLink | null> {
			const rows = await db
				.select()
				.from(delegationChains)
				.where(
					and(
						eq(delegationChains.fromAgentId, from),
						eq(delegationChains.toAgentId, to),
						eq(delegationChains.status, "active"),
					),
				)
				.orderBy(asc(delegationChains.createdAt), asc(delegationChains.id));
			const liveness = createDelegatorLiveness(db, now);
			for (const row of rows) {
				if (row.expiresAt.getTime() <= now.getTime()) continue;
				if ((await liveness.linkState(row)) === "live") {
					return { id: row.id, expiresAt: row.expiresAt };
				}
			}
			return null;
		},

		async check(binding, now): Promise<McpBindingVerdict> {
			if (!wellFormed(binding)) return { live: false, reason: "invalid", id: "" };
			let validUntil = MCP_BINDING_NO_EXPIRY;

			if (binding.lnk.length > 0) {
				const rows = await db
					.select()
					.from(delegationChains)
					.where(inArray(delegationChains.id, [...new Set(binding.lnk)]));
				const byId = new Map(rows.map((r) => [r.id, r]));
				for (const [i, id] of binding.lnk.entries()) {
					const row = byId.get(id);
					// A deleted link lends nothing: treat it as revoked.
					if (!row) return { live: false, reason: "delegation_revoked", id };
					// The signed claim names the pair; a row that links other agents is not this link.
					if (row.fromAgentId !== binding.agt[i] || row.toAgentId !== binding.agt[i + 1]) {
						return { live: false, reason: "invalid", id };
					}
					if (row.status === "revoked") return { live: false, reason: "delegation_revoked", id };
					if (row.status !== "active" || row.expiresAt.getTime() <= now.getTime()) {
						return { live: false, reason: "delegation_expired", id };
					}
					validUntil = earlier(validUntil, row.expiresAt);
				}
			}

			const found = await agentRows(binding.agt);
			for (const id of binding.agt) {
				const row = found.get(id);
				if (!row) return { live: false, reason: "agent_revoked", id };
				if (row.status === "expired") return { live: false, reason: "agent_expired", id };
				if (row.status !== "active") return { live: false, reason: "agent_revoked", id };
				if (row.expiresAt !== null && row.expiresAt.getTime() <= now.getTime()) {
					return { live: false, reason: "agent_expired", id };
				}
				validUntil = earlier(validUntil, row.expiresAt);
			}

			// The root agent may itself hold delegated authority: it must still trace to a live delegator.
			const root = binding.agt[0] as string;
			const upstream = await createDelegatorLiveness(db, now).delegatorState(root);
			if (upstream === "revoked") return { live: false, reason: "delegation_revoked", id: root };
			if (upstream === "expired") return { live: false, reason: "delegation_expired", id: root };

			return { live: true, validUntil };
		},
	};
}
