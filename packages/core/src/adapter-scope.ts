/**
 * Owner scoping for the adapter management routes.
 *
 * When an adapter runs with the default session resolver, a signed-in user is
 * only allowed to act on their own agents, delegations and audit rows. When
 * the host passed its own `authenticate` resolver (or opted out of
 * authentication for local development) the scope is unrestricted and every
 * check passes, which keeps the host's explicit trust decision intact.
 *
 * The scope is built once per request by `AdapterGuard.resolve`. Adapters only
 * need to call the matching check before a handler touches a resource.
 *
 * Every check fails closed: if ownership cannot be determined the answer is a
 * denial. Resources the caller does not own are reported as "not found" so the
 * routes do not reveal which ids exist.
 */

import type { TheAuth } from "./theauth.js";
import type { AgentFilter, AuditExportOptions, AuditFilter } from "./types.js";

/** Why a request was refused. `status` and `code` map straight onto the error body. */
export interface ScopeDenial {
	status: 403 | 404;
	code: "FORBIDDEN" | "NOT_FOUND";
	message: string;
}

/** Outcome of rewriting a filter: the scoped value, or a denial. */
export type ScopeResult<T> = { ok: true; value: T } | { ok: false; denial: ScopeDenial };

/** What the signed-in caller may touch on the management routes. */
export interface AdapterScope {
	/**
	 * True when the caller is limited to their own resources (default session
	 * resolver). False when the host supplied `authenticate` or disabled
	 * authentication, in which case every check below passes.
	 */
	readonly restricted: boolean;
	/** The caller id when restricted, otherwise null. */
	readonly ownerId: string | null;
	/** `POST /agents`: the new agent must be owned by the caller. */
	checkAgentCreate(ownerId: string): ScopeDenial | null;
	/** Routes keyed by an agent id: get, update, revoke, rotate, authorize, delegate (from), list chains. */
	checkAgent(agentId: string): Promise<ScopeDenial | null>;
	/** Routes keyed by a delegation chain id: revoke. */
	checkChain(chainId: string): Promise<ScopeDenial | null>;
	/** `GET /agents`, `GET /dashboard/agents`: pin the owner filter to the caller. */
	scopeAgentFilter(filter: AgentFilter): ScopeResult<AgentFilter>;
	/** `GET /audit`, `GET /dashboard/audit`: pin the user filter to the caller. */
	scopeAuditFilter(filter: AuditFilter): ScopeResult<AuditFilter>;
	/** `GET /audit/export`: pin the user filter to the caller. */
	scopeAuditExport(options: AuditExportOptions): ScopeResult<AuditExportOptions>;
	/**
	 * `GET /dashboard/stats`: the user id the aggregate must be limited to, or
	 * undefined when the caller may see the whole instance.
	 */
	statsOwnerId(): string | undefined;
}

const FORBIDDEN: ScopeDenial = {
	status: 403,
	code: "FORBIDDEN",
	message: "You can only act on your own resources",
};

function notFound(what: string): ScopeDenial {
	return { status: 404, code: "NOT_FOUND", message: `${what} not found` };
}

/** Scope with no limits, used for custom resolvers and the local-dev opt-out. */
export function createUnrestrictedScope(): AdapterScope {
	return {
		restricted: false,
		ownerId: null,
		checkAgentCreate: () => null,
		checkAgent: async () => null,
		checkChain: async () => null,
		scopeAgentFilter: (filter) => ({ ok: true, value: filter }),
		scopeAuditFilter: (filter) => ({ ok: true, value: filter }),
		scopeAuditExport: (options) => ({ ok: true, value: options }),
		statsOwnerId: () => undefined,
	};
}

/** Scope limited to the resources owned by `ownerId`. */
export function createOwnerScope(theauth: TheAuth, ownerId: string): AdapterScope {
	async function ownsAgent(agentId: string): Promise<boolean> {
		try {
			const agent = await theauth.agent.get(agentId);
			return agent !== null && agent !== undefined && agent.ownerId === ownerId;
		} catch {
			return false;
		}
	}

	return {
		restricted: true,
		ownerId,
		checkAgentCreate: (requestedOwner) => (requestedOwner === ownerId ? null : FORBIDDEN),
		async checkAgent(agentId) {
			return (await ownsAgent(agentId)) ? null : notFound("Agent");
		},
		async checkChain(chainId) {
			try {
				const mine = await theauth.agent.list({ userId: ownerId });
				for (const agent of mine) {
					const chains = await theauth.delegation.listChains(agent.id);
					if (chains.some((chain) => chain.id === chainId)) return null;
				}
			} catch {
				// fall through: unknown ownership is a denial
			}
			return notFound("Delegation");
		},
		scopeAgentFilter(filter) {
			if (filter.userId !== undefined && filter.userId !== ownerId) {
				return { ok: false, denial: FORBIDDEN };
			}
			return { ok: true, value: { ...filter, userId: ownerId } };
		},
		scopeAuditFilter(filter) {
			if (filter.userId !== undefined && filter.userId !== ownerId) {
				return { ok: false, denial: FORBIDDEN };
			}
			return { ok: true, value: { ...filter, userId: ownerId } };
		},
		scopeAuditExport(options) {
			if (options.userId !== undefined && options.userId !== ownerId) {
				return { ok: false, denial: FORBIDDEN };
			}
			return { ok: true, value: { ...options, userId: ownerId } };
		},
		statsOwnerId: () => ownerId,
	};
}
