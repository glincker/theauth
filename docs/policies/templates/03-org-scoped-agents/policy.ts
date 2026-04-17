/**
 * Template 03, Org-scoped agents (multi-tenant)
 *
 * Each tenant gets its own set of resources under a namespaced prefix, e.g.
 * "org:acme:*". An agent belonging to org "acme" is only granted permissions
 * under that prefix. Agents from different orgs cannot see each other's data
 * because the resource pattern never matches.
 *
 * The wildcard "org:acme:*" relies on the engine's matchResource() which
 * returns true when any segment is "*" and all preceding segments match.
 *
 * Seeding: insert the permissions below with the correct agentId, then pass
 * subject.orgId so that RBAC role lookups are scoped to the right org.
 */

import type { Permission } from "../../../../packages/core/src/types.js";

/**
 * Build the permission set for an agent in the given org.
 * Resource pattern "org:<orgSlug>:*" matches any resource in that org.
 */
export function buildOrgPermissions(orgSlug: string): Permission[] {
	return [
		{
			resource: `org:${orgSlug}:*`,
			actions: ["read", "write"],
		},
	];
}

/** Example: permissions for the "acme" tenant's agent. */
export const acmeAgentPermissions: Permission[] = buildOrgPermissions("acme");

/** Example: permissions for the "globex" tenant's agent. */
export const globexAgentPermissions: Permission[] = buildOrgPermissions("globex");
