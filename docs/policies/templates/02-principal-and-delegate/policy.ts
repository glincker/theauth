/**
 * Template 02, Principal and delegated agent
 *
 * The principal agent has full read+write access to a resource. A delegated
 * agent receives only read access, and that grant expires at a fixed date.
 * Expired delegations are rejected by the engine because fetchDelegatedPermissions
 * filters on `expiresAt > now()`.
 *
 * Seeding:
 *   1. Insert principalPermissions into kavach_permissions (agentId = principal).
 *   2. Insert a row into kavach_delegation_chains:
 *        fromAgentId = principal, toAgentId = delegate,
 *        permissions = delegatedPermissions, status = "active",
 *        expiresAt = <future date>.
 */

import type { Permission } from "../../../../packages/core/src/types.js";

/** Permissions granted directly to the principal agent. */
export const principalPermissions: Permission[] = [
	{
		resource: "reports:monthly",
		actions: ["read", "write"],
	},
];

/**
 * Subset of permissions the principal delegates to another agent.
 * These are stored in kavach_delegation_chains.permissions, not in
 * kavach_permissions directly.
 */
export const delegatedPermissions: Permission[] = [
	{
		resource: "reports:monthly",
		actions: ["read"],
	},
];
