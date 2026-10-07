import { and, eq } from "drizzle-orm";
import { generateId } from "../crypto/web-crypto.js";
import type { Database } from "../db/database.js";
import { delegationChains } from "../db/schema.js";
import type { DelegateInput, DelegationChain, Permission } from "../types.js";

interface DelegationModuleConfig {
	db: Database;
}

/**
 * Verify that delegated permissions are a subset of the parent's permissions.
 * A child agent cannot have more permissions than its parent.
 */
function isPermissionSubset(parentPerms: Permission[], childPerms: Permission[]): boolean {
	for (const childPerm of childPerms) {
		const parentMatch = parentPerms.find((p) => {
			// Check resource match (child must be same or more specific)
			if (!isResourceSubset(p.resource, childPerm.resource)) return false;

			// Check actions match (child must have same or fewer actions)
			for (const action of childPerm.actions) {
				if (!p.actions.includes(action) && !p.actions.includes("*")) return false;
			}

			return true;
		});

		if (!parentMatch) return false;
	}

	return true;
}

/**
 * Check if childResource is the same as or more specific than parentResource.
 * "mcp:github:*" contains "mcp:github:read"
 * "mcp:*" contains "mcp:github:*"
 * "*" contains everything
 */
function isResourceSubset(parentResource: string, childResource: string): boolean {
	if (parentResource === "*") return true;
	if (parentResource === childResource) return true;

	const parentParts = parentResource.split(":");
	const childParts = childResource.split(":");

	for (let i = 0; i < parentParts.length; i++) {
		if (parentParts[i] === "*") return true;
		if (parentParts[i] !== childParts[i]) return false;
	}

	return parentParts.length <= childParts.length;
}

export type DelegationErrorCode = "DELEGATION_PERMISSION_SUBSET" | "DELEGATION_DEPTH_EXCEEDED";

/**
 * Typed error for delegation requests that are invalid by caller input.
 * Adapters map it to HTTP 400 using `code`.
 */
export class DelegationError extends Error {
	readonly code: DelegationErrorCode;

	constructor(code: DelegationErrorCode, message: string) {
		super(message);
		this.name = "DelegationError";
		this.code = code;
	}
}

/**
 * Create the delegation module.
 * Handles agent-to-agent permission delegation with chain tracking.
 */
export function createDelegationModule(config: DelegationModuleConfig) {
	const { db } = config;

	async function delegate(
		input: DelegateInput,
		parentPermissions: Permission[],
	): Promise<DelegationChain> {
		// Validate permissions are a subset
		if (!isPermissionSubset(parentPermissions, input.permissions)) {
			throw new DelegationError(
				"DELEGATION_PERMISSION_SUBSET",
				"Delegated permissions must be a subset of the parent agent's permissions. " +
					"A child agent cannot have more access than its parent.",
			);
		}

		// Check delegation depth
		const existingChains = await db
			.select()
			.from(delegationChains)
			.where(
				and(eq(delegationChains.toAgentId, input.fromAgent), eq(delegationChains.status, "active")),
			);

		const currentDepth =
			existingChains.length > 0 ? Math.max(...existingChains.map((c) => c.depth)) + 1 : 1;

		const maxDepth = input.maxDepth ?? 3;

		if (currentDepth > maxDepth) {
			throw new DelegationError(
				"DELEGATION_DEPTH_EXCEEDED",
				`Delegation depth ${currentDepth} exceeds maximum allowed depth of ${maxDepth}. ` +
					"This prevents infinite delegation chains.",
			);
		}

		const id = generateId();
		const now = new Date();

		await db.insert(delegationChains).values({
			id,
			fromAgentId: input.fromAgent,
			toAgentId: input.toAgent,
			permissions: input.permissions.map((p) => ({
				resource: p.resource,
				actions: p.actions,
			})),
			depth: currentDepth,
			maxDepth,
			status: "active",
			expiresAt: input.expiresAt,
			createdAt: now,
		});

		return {
			id,
			fromAgent: input.fromAgent,
			toAgent: input.toAgent,
			permissions: input.permissions,
			expiresAt: input.expiresAt,
			depth: currentDepth,
			createdAt: now,
		};
	}

	/**
	 * Revoke a delegation chain. Revoking a parent chain also revokes all children.
	 */
	async function revokeDelegation(chainId: string): Promise<void> {
		const chain = await db
			.select()
			.from(delegationChains)
			.where(eq(delegationChains.id, chainId))
			.limit(1);

		if (!chain[0]) throw new Error(`Delegation chain ${chainId} not found.`);

		// Revoke this chain
		await db
			.update(delegationChains)
			.set({ status: "revoked" })
			.where(eq(delegationChains.id, chainId));

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
			await revokeDelegation(child.id);
		}
	}

	/**
	 * Get the effective permissions for an agent, including delegated permissions.
	 */
	async function getEffectivePermissions(agentId: string): Promise<Permission[]> {
		const chains = await db
			.select()
			.from(delegationChains)
			.where(and(eq(delegationChains.toAgentId, agentId), eq(delegationChains.status, "active")));

		// Filter expired chains
		const now = new Date();
		const activeChains = chains.filter((c) => c.expiresAt > now);

		// Collect all delegated permissions
		const delegatedPerms: Permission[] = [];
		for (const chain of activeChains) {
			for (const perm of chain.permissions) {
				delegatedPerms.push({
					resource: perm.resource,
					actions: perm.actions,
				});
			}
		}

		return delegatedPerms;
	}

	/**
	 * List all delegation chains for an agent (as source or target).
	 */
	async function listChains(agentId: string): Promise<DelegationChain[]> {
		const chains = await db
			.select()
			.from(delegationChains)
			.where(eq(delegationChains.fromAgentId, agentId));

		return chains.map((c) => ({
			id: c.id,
			fromAgent: c.fromAgentId,
			toAgent: c.toAgentId,
			permissions: c.permissions.map((p) => ({
				resource: p.resource,
				actions: p.actions,
			})),
			expiresAt: c.expiresAt,
			depth: c.depth,
			createdAt: c.createdAt,
		}));
	}

	return { delegate, revokeDelegation, getEffectivePermissions, listChains };
}
