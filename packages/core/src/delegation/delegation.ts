import { and, eq, or } from "drizzle-orm";
import { canonicalJson } from "../audit/chain.js";
import { recordAuditEvent } from "../audit/record.js";
import { generateId } from "../crypto/web-crypto.js";
import type { Database } from "../db/database.js";
import { delegationChains, permissions } from "../db/schema.js";
import { revocationRowExpiry } from "../mcp/revocation-bus.js";
import type { McpRevocationBus } from "../mcp/revocation-types.js";
import type { ResourceMatching } from "../policy/resource-match.js";
import type {
	DelegateInput,
	DelegationChain,
	Permission,
	PermissionConstraints,
} from "../types.js";
import { assertValidExpiry } from "../validation.js";
import { narrowConstraints } from "./constraints.js";
import { resolveLineage } from "./lineage.js";
import { loadLiveInboundRows } from "./liveness.js";
import { isPermissionSubset, resourcesOverlap } from "./subset.js";

interface DelegationModuleConfig {
	db: Database;
	/** Receives every revoked link id so the shared MCP denylist and in-process caches see it. Optional. */
	revocations?: McpRevocationBus;
	/** Must equal the top level `resourceMatching`. Decides what counts as a subset of the parent. Default `colon`. */
	resourceMatching?: ResourceMatching;
}

/** Active, unexpired permissions delegated to an agent by delegators that are still live (an agent delegator that is revoked, suspended or expired lends nothing), constraints included. The one merge source shared by auth.authorize, policy.evaluate and delegate(). */
export async function getDelegatedPermissions(
	db: Database,
	agentId: string,
	matching: ResourceMatching = "colon",
): Promise<Permission[]> {
	const chains = await loadLiveInboundRows(db, agentId, new Date(), matching);
	return chains.flatMap((c) => (c.permissions as Permission[]).map((p) => ({ ...p })));
}

/**
 * Apply the parent's constraints to each requested permission, one action at a time. For every action the first parent rule (in engine order) that overlaps the child's resource and grants that action supplies the constraints, so a rule that gates an action (for example requireApproval) is never skipped because a later rule covers more actions. Actions whose narrowed constraints are identical stay in one permission, others are split. Constraints only ever narrow.
 */
function inheritConstraints(
	parentPerms: Permission[],
	requested: Permission[],
	mode: ResourceMatching,
): Permission[] {
	const out: Permission[] = [];
	for (const child of requested) {
		const groups = new Map<string, { actions: string[]; constraints?: PermissionConstraints }>();
		for (const action of child.actions) {
			const parent = parentPerms.find(
				(p) =>
					resourcesOverlap(p.resource, child.resource, mode) &&
					(p.actions.includes(action) || p.actions.includes("*")),
			);
			const constraints = narrowConstraints(parent?.constraints, child.constraints);
			const key = constraints ? canonicalJson(constraints) : "";
			const group = groups.get(key);
			if (group) group.actions.push(action);
			else groups.set(key, { actions: [action], constraints });
		}
		const { constraints: _requested, ...withoutConstraints } = child;
		for (const group of groups.values()) {
			out.push(
				group.constraints
					? { ...withoutConstraints, actions: group.actions, constraints: group.constraints }
					: { ...withoutConstraints, actions: group.actions },
			);
		}
	}
	return out;
}

export type DelegationErrorCode =
	| "DELEGATION_PERMISSION_SUBSET"
	| "DELEGATION_DEPTH_EXCEEDED"
	| "DELEGATION_PARENT_REVOKED";

/** Typed error for delegation requests that are invalid by caller input. Adapters map it to HTTP 400 using `code`. */
export class DelegationError extends Error {
	readonly code: DelegationErrorCode;

	constructor(code: DelegationErrorCode, message: string) {
		super(message);
		this.name = "DelegationError";
		this.code = code;
	}
}

/** Collects what the revocation push needs while a cascade runs. */
interface RevokeSink {
	expiries: Map<string, Date>;
	rootToAgent?: string;
}

/** Create the delegation module. Handles agent-to-agent permission delegation with chain tracking. */
export function createDelegationModule(config: DelegationModuleConfig) {
	const { db, revocations } = config;
	const matching = config.resourceMatching ?? "colon";

	/**
	 * Create a delegation from `input.fromAgent` to `input.toAgent`.
	 * The parent's authority is read from storage, never from the caller: its own permission rows plus the active, unexpired chains that delegate to it.
	 */
	async function delegate(input: DelegateInput): Promise<DelegationChain> {
		// Required on a delegation, so a missing value is as invalid as an Invalid Date.
		assertValidExpiry(input.expiresAt ?? null);
		const now = new Date();

		const ownRows = await db
			.select()
			.from(permissions)
			.where(eq(permissions.agentId, input.fromAgent));
		const ownPermissions: Permission[] = ownRows.map((r) => ({
			resource: r.resource,
			actions: r.actions,
			constraints: r.constraints ?? undefined,
		}));

		const inbound = await loadLiveInboundRows(db, input.fromAgent, now, matching);
		const inboundPermissions: Permission[] = inbound.flatMap((c) =>
			(c.permissions as Permission[]).map((p) => ({ ...p })),
		);

		// Validate permissions are a subset of what the parent actually holds
		if (
			!isPermissionSubset([...ownPermissions, ...inboundPermissions], input.permissions, matching)
		) {
			throw new DelegationError(
				"DELEGATION_PERMISSION_SUBSET",
				"Delegated permissions must be a subset of the parent agent's permissions. " +
					"A child agent cannot have more access than its parent.",
			);
		}

		// A child never outlives the authority it was derived from. If the
		// parent's own permissions cover the request, no inbound chain limits it.
		let expiresAt = input.expiresAt;
		if (inbound.length > 0 && !isPermissionSubset(ownPermissions, input.permissions, matching)) {
			const parentExpiry = new Date(
				inbound.reduce((min, c) => Math.min(min, c.expiresAt.getTime()), Infinity),
			);
			if (expiresAt > parentExpiry) expiresAt = parentExpiry;
		}

		// Depth: one deeper than the deepest inbound chain, within the stricter
		// of the requested and inherited limits.
		const currentDepth =
			inbound.length > 0 ? inbound.reduce((max, c) => Math.max(max, c.depth), 0) + 1 : 1;
		const maxDepth = inbound.reduce((min, c) => Math.min(min, c.maxDepth), input.maxDepth ?? 3);

		if (currentDepth > maxDepth) {
			throw new DelegationError(
				"DELEGATION_DEPTH_EXCEEDED",
				`Delegation depth ${currentDepth} exceeds maximum allowed depth of ${maxDepth}. ` +
					"This prevents infinite delegation chains.",
			);
		}

		const id = generateId();
		const granted = inheritConstraints(
			[...ownPermissions, ...inboundPermissions],
			input.permissions,
			matching,
		);

		await db.insert(delegationChains).values({
			id,
			fromAgentId: input.fromAgent,
			toAgentId: input.toAgent,
			permissions: granted,
			depth: currentDepth,
			maxDepth,
			status: "active",
			expiresAt,
			createdAt: now,
		});

		// Revocation race: if the parent's inbound chain was revoked between the
		// read above and the insert, the cascade may already have run and missed
		// this row. Re-check and roll the insert back rather than leave an orphan
		// grant. (Depth is derived from immutable chain rows, so it cannot drift.)
		if (inbound.length > 0 && !isPermissionSubset(ownPermissions, input.permissions, matching)) {
			const stillActive = await db
				.select()
				.from(delegationChains)
				.where(
					and(
						eq(delegationChains.toAgentId, input.fromAgent),
						eq(delegationChains.status, "active"),
					),
				);
			const liveIds = new Set(stillActive.map((c) => c.id));
			if (!inbound.some((c) => liveIds.has(c.id))) {
				await db.delete(delegationChains).where(eq(delegationChains.id, id));
				throw new DelegationError(
					"DELEGATION_PARENT_REVOKED",
					"The parent's delegation was revoked while this delegation was being created.",
				);
			}
		}

		const lineage = await resolveLineage(db, input.toAgent);
		await recordAuditEvent(db, {
			agentId: input.toAgent,
			action: "delegate",
			event: "delegation.create",
			resource: `delegation:${id}`,
			result: "allowed",
			actorId: input.fromAgent,
			subjectId: lineage.rootOwnerId,
			delegationChain: lineage.path,
			parameters: {
				delegationId: id,
				fromAgent: input.fromAgent,
				toAgent: input.toAgent,
				rootOwnerId: lineage.rootOwnerId,
				hops: lineage.hops,
				permissions: granted,
				depth: currentDepth,
				expiresAt: expiresAt.toISOString(),
			},
		});

		return {
			id,
			fromAgent: input.fromAgent,
			toAgent: input.toAgent,
			permissions: granted,
			expiresAt,
			depth: currentDepth,
			createdAt: now,
			rootOwnerId: lineage.rootOwnerId,
			path: lineage.path,
		};
	}

	/** Revoke a delegation chain. Revoking a parent chain also revokes all children. Returns the ids of the chains that were active and are now revoked, this one and its descendants. Each revoked link writes a chained `delegation.revoke` audit row (best effort) on the delegate's chain; pass `revokedBy` to record who did it. */
	async function revokeDelegation(
		chainId: string,
		options: { revokedBy?: string } = {},
	): Promise<string[]> {
		const sink: RevokeSink = { expiries: new Map() };
		const revoked = await revokeLink(chainId, options.revokedBy ?? null, chainId, null, sink);
		await pushRevoked(chainId, revoked, sink, options.revokedBy);
		return revoked;
	}

	/** Feed the revoked link ids (cascade included) to the revocation bus. Never throws: the chain rows are already revoked. */
	async function pushRevoked(
		rootId: string,
		revoked: string[],
		sink: RevokeSink,
		revokedBy: string | undefined,
	): Promise<void> {
		if (!revocations || revoked.length === 0) return;
		try {
			const now = new Date();
			let userId: string | undefined;
			if (sink.rootToAgent) {
				try {
					userId = (await resolveLineage(db, sink.rootToAgent)).rootOwnerId;
				} catch {
					// The subject is optional; the denylist rows matter more.
				}
			}
			await revocations.publish(
				{
					kind: "dlg",
					ids: revoked,
					revokedAt: now,
					reason: "delegation.revoke",
					...(userId ? { userId } : {}),
					sourceId: rootId,
				},
				revoked.map((id) => ({
					kind: "dlg" as const,
					id,
					expiresAt: revocationRowExpiry(sink.expiries.get(id), now),
					reason: "delegation.revoke",
					sourceId: revokedBy ?? rootId,
				})),
			);
		} catch {
			// The bus reports its own failures; a revoke must not fail after it committed.
		}
	}

	async function revokeLink(
		chainId: string,
		revokedBy: string | null,
		rootChainId: string,
		parentChainId: string | null,
		sink: RevokeSink,
	): Promise<string[]> {
		const chain = await db
			.select()
			.from(delegationChains)
			.where(eq(delegationChains.id, chainId))
			.limit(1);

		if (!chain[0]) throw new Error(`Delegation chain ${chainId} not found.`);

		const wasActive = chain[0].status === "active";
		const revoked: string[] = wasActive ? [chainId] : [];
		if (wasActive) {
			sink.expiries.set(chainId, chain[0].expiresAt);
			if (parentChainId === null) sink.rootToAgent = chain[0].toAgentId;
		}

		await db
			.update(delegationChains)
			.set({ status: "revoked" })
			.where(eq(delegationChains.id, chainId));

		if (wasActive) {
			await recordAuditEvent(db, {
				agentId: chain[0].toAgentId,
				action: "delegate",
				event: "delegation.revoke",
				resource: `delegation:${chainId}`,
				result: "allowed",
				...(revokedBy ? { actorId: revokedBy } : {}),
				parameters: {
					delegationId: chainId,
					fromAgent: chain[0].fromAgentId,
					toAgent: chain[0].toAgentId,
					revokedBy,
					cascade: parentChainId !== null,
					cascadeFrom: parentChainId,
					rootDelegationId: rootChainId,
				},
			});
		}

		// Cascade: revoke all chains where the to-agent of this chain is the from-agent
		const childChains = await db
			.select()
			.from(delegationChains)
			.where(
				and(
					eq(delegationChains.fromAgentId, chain[0].toAgentId),
					eq(delegationChains.status, "active"),
				),
			);

		for (const child of childChains) {
			revoked.push(...(await revokeLink(child.id, revokedBy, rootChainId, chainId, sink)));
		}
		return revoked;
	}

	/** Revoke every active chain where the agent is source or target, plus the child chains that cascade from them. Returns the revoked chain ids. */
	async function revokeAllForAgent(
		agentId: string,
		options: { revokedBy?: string } = {},
	): Promise<string[]> {
		const rows = await db
			.select()
			.from(delegationChains)
			.where(
				and(
					eq(delegationChains.status, "active"),
					or(eq(delegationChains.fromAgentId, agentId), eq(delegationChains.toAgentId, agentId)),
				),
			);
		const revoked: string[] = [];
		for (const row of rows) {
			// An earlier cascade in this loop may already have revoked it.
			const [current] = await db
				.select()
				.from(delegationChains)
				.where(eq(delegationChains.id, row.id))
				.limit(1);
			if (current?.status !== "active") continue;
			revoked.push(...(await revokeDelegation(row.id, options)));
		}
		return revoked;
	}

	/** Get the effective permissions for an agent, including delegated permissions. */
	async function getEffectivePermissions(agentId: string): Promise<Permission[]> {
		return getDelegatedPermissions(db, agentId, matching);
	}

	/** List the delegation chains an agent created as the delegator (`fromAgentId`). Inbound chains where the agent is the delegate are not included. */
	async function listChains(agentId: string): Promise<DelegationChain[]> {
		const chains = await db
			.select()
			.from(delegationChains)
			.where(eq(delegationChains.fromAgentId, agentId));

		return chains.map((c) => ({
			id: c.id,
			fromAgent: c.fromAgentId,
			toAgent: c.toAgentId,
			permissions: c.permissions as Permission[],
			expiresAt: c.expiresAt,
			depth: c.depth,
			createdAt: c.createdAt,
		}));
	}

	return { delegate, revokeDelegation, revokeAllForAgent, getEffectivePermissions, listChains };
}
