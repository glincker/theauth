/**
 * RBAC role expansion: resolve a user's effective permissions from org memberships.
 *
 * Joins orgMembers → orgRoles for the given userId (and optionally orgId),
 * parses the stored "resource:action" strings into Permission objects, and
 * deduplicates across roles.
 */

import { and, eq } from "drizzle-orm";
import type { Database } from "../db/database.js";
import { orgMembers, orgRoles } from "../db/schema.js";
import type { Permission } from "../types.js";

// ─────────────────────────────────────────────────────────────────────────────
// Public interface
// ─────────────────────────────────────────────────────────────────────────────

export interface RbacResolver {
	/**
	 * Return the union of permissions granted by every org role the user holds.
	 *
	 * When `orgId` is supplied, only the membership in that one org is
	 * considered. When omitted, memberships across all orgs are gathered and
	 * their permissions merged (deduplicated by resource+actions).
	 */
	resolveRolePermissions(input: { userId: string; orgId?: string }): Promise<Permission[]>;
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Parse a stored "resource:action" string into a { resource, action } pair.
 * Splits on the LAST colon so multi-segment resources like "mcp:github:read"
 * parse to resource="mcp:github", action="read".
 */
function parsePermissionString(raw: string): { resource: string; action: string } | null {
	const idx = raw.lastIndexOf(":");
	if (idx === -1) return null;
	const resource = raw.slice(0, idx);
	const action = raw.slice(idx + 1);
	if (!resource || !action) return null;
	return { resource, action };
}

/**
 * Collapse a flat list of "resource:action" strings into Permission objects,
 * grouping actions that share the same resource.
 */
function toPermissions(rawStrings: string[]): Permission[] {
	const map = new Map<string, Set<string>>();
	for (const raw of rawStrings) {
		const parsed = parsePermissionString(raw);
		if (!parsed) continue;
		const existing = map.get(parsed.resource);
		if (existing) {
			existing.add(parsed.action);
		} else {
			map.set(parsed.resource, new Set([parsed.action]));
		}
	}
	return Array.from(map.entries()).map(([resource, actionsSet]) => ({
		resource,
		actions: Array.from(actionsSet).sort(),
	}));
}

/**
 * Deduplicate a list of Permission objects by their resource+actions fingerprint.
 */
function deduplicate(permissions: Permission[]): Permission[] {
	const seen = new Set<string>();
	const result: Permission[] = [];
	for (const perm of permissions) {
		const key = `${perm.resource}|${[...perm.actions].sort().join(",")}`;
		if (!seen.has(key)) {
			seen.add(key);
			result.push(perm);
		}
	}
	return result;
}

// ─────────────────────────────────────────────────────────────────────────────
// Factory
// ─────────────────────────────────────────────────────────────────────────────

export function createRbacResolver(deps: { db: Database }): RbacResolver {
	const { db } = deps;

	async function resolveRolePermissions(input: {
		userId: string;
		orgId?: string;
	}): Promise<Permission[]> {
		const { userId, orgId } = input;

		// One join per call instead of N+1: pull the role permissions for every
		// matching membership in a single query.
		const baseWhere = orgId
			? and(eq(orgMembers.userId, userId), eq(orgMembers.orgId, orgId))
			: eq(orgMembers.userId, userId);

		const roleRows = await db
			.select({ permissions: orgRoles.permissions })
			.from(orgMembers)
			.innerJoin(
				orgRoles,
				and(eq(orgRoles.orgId, orgMembers.orgId), eq(orgRoles.name, orgMembers.role)),
			)
			.where(baseWhere);

		if (roleRows.length === 0) return [];

		const allRawPermissions = roleRows.flatMap((r) => r.permissions);
		if (allRawPermissions.length === 0) return [];

		return deduplicate(toPermissions(allRawPermissions));
	}

	return { resolveRolePermissions };
}
