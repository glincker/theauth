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
 * Splits on the first colon only so resources like "mcp:github" are preserved.
 */
function parsePermissionString(raw: string): { resource: string; action: string } | null {
	const idx = raw.indexOf(":");
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

		// 1. Fetch the relevant orgMember rows.
		const memberRows = orgId
			? await db
					.select({ role: orgMembers.role, orgId: orgMembers.orgId })
					.from(orgMembers)
					.where(and(eq(orgMembers.userId, userId), eq(orgMembers.orgId, orgId)))
			: await db
					.select({ role: orgMembers.role, orgId: orgMembers.orgId })
					.from(orgMembers)
					.where(eq(orgMembers.userId, userId));

		if (memberRows.length === 0) return [];

		// 2. For each membership, fetch the matching orgRole and collect raw strings.
		const allRawPermissions: string[] = [];
		for (const member of memberRows) {
			const roleRows = await db
				.select({ permissions: orgRoles.permissions })
				.from(orgRoles)
				.where(and(eq(orgRoles.orgId, member.orgId), eq(orgRoles.name, member.role)));
			for (const row of roleRows) {
				allRawPermissions.push(...row.permissions);
			}
		}

		if (allRawPermissions.length === 0) return [];

		// 3. Parse, group by resource, then deduplicate across roles.
		return deduplicate(toPermissions(allRawPermissions));
	}

	return { resolveRolePermissions };
}
