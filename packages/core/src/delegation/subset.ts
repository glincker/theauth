import { matchResource } from "../policy/abac.js";
import type { ResourceMatching } from "../policy/resource-match.js";
import { pathPatternsMayOverlap } from "../policy/resource-match.js";
import type { Permission } from "../types.js";

/** Verify that delegated permissions are a subset of the parent's permissions. A child agent cannot have more permissions than its parent. */
export function isPermissionSubset(
	parentPerms: Permission[],
	childPerms: Permission[],
	mode: ResourceMatching = "colon",
): boolean {
	for (const childPerm of childPerms) {
		const parentMatch = parentPerms.find((p) => {
			// Check resource match (child must be same or more specific)
			if (!isResourceSubset(p.resource, childPerm.resource, mode)) return false;

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
 * Check if childResource is the same as or more specific than parentResource. "mcp:github:*" contains "mcp:github:read" "mcp:*" contains "mcp:github:*" "*" contains everything.
 * It is the runtime matcher applied to the child as a pattern, so a child is never allowed more than the parent could use itself. A wildcard in the child is covered only by an equal or broader wildcard.
 */
export function isResourceSubset(
	parentResource: string,
	childResource: string,
	mode: ResourceMatching = "colon",
): boolean {
	if (parentResource === "*") return true;
	if (parentResource === childResource) return true;
	return matchResource(parentResource, childResource, mode);
}

/** The pre-fix containment test. It also said yes when the parent was a shorter exact prefix of the child, so it is only used to decide which parent rule's constraints a child inherits (over-matching there only adds constraints). */
function legacyContains(parentResource: string, childResource: string): boolean {
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

/** True when the two resource patterns can select a common resource, so either one may gate the other. Errs toward true. */
export function resourcesOverlap(
	parent: string,
	child: string,
	mode: ResourceMatching = "colon",
): boolean {
	if (legacyContains(parent, child) || legacyContains(child, parent)) return true;
	return mode === "path" && pathPatternsMayOverlap(parent, child);
}
