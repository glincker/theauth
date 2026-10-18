import type { Permission } from "../types.js";

/** Verify that delegated permissions are a subset of the parent's permissions. A child agent cannot have more permissions than its parent. */
export function isPermissionSubset(parentPerms: Permission[], childPerms: Permission[]): boolean {
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

/** Check if childResource is the same as or more specific than parentResource. "mcp:github:*" contains "mcp:github:read" "mcp:*" contains "mcp:github:*" "*" contains everything */
export function isResourceSubset(parentResource: string, childResource: string): boolean {
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
