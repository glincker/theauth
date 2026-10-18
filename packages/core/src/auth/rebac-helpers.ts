import type { Result } from "../mcp/types.js";
import type { PermissionRuleSet, Relationship, ResourceNode } from "./rebac-types.js";

export const DEFAULT_PERMISSION_RULES: Record<string, PermissionRuleSet> = {
	org: {
		implies: {
			owner: ["admin", "editor", "viewer", "member"],
			admin: ["editor", "viewer", "member"],
			editor: ["viewer"],
			member: ["viewer"],
		},
	},
	workspace: {
		implies: {
			owner: ["admin", "editor", "viewer", "member"],
			admin: ["editor", "viewer", "member"],
			editor: ["viewer"],
			member: ["viewer"],
		},
		inheritFromParent: true,
	},
	project: {
		implies: {
			owner: ["admin", "editor", "viewer", "member"],
			admin: ["editor", "viewer", "member"],
			editor: ["viewer"],
			member: ["viewer"],
		},
		inheritFromParent: true,
	},
	document: {
		implies: {
			owner: ["editor", "viewer"],
			editor: ["viewer"],
		},
		inheritFromParent: true,
	},
	resource: {
		implies: {
			owner: ["editor", "viewer"],
			editor: ["viewer"],
		},
		inheritFromParent: true,
	},
};

export function ok<T>(data: T): Result<T> {
	return { success: true, data };
}

export function fail<T>(code: string, message: string): Result<T> {
	return { success: false, error: { code, message } };
}

export function rowToResource(row: {
	id: string;
	type: string;
	parentId: string | null;
	parentType: string | null;
}): ResourceNode {
	return {
		id: row.id,
		type: row.type,
		...(row.parentId ? { parentId: row.parentId } : {}),
		...(row.parentType ? { parentType: row.parentType } : {}),
	};
}

export function rowToRelationship(row: {
	id: string;
	subjectType: string;
	subjectId: string;
	relation: string;
	objectType: string;
	objectId: string;
	createdAt: Date;
}): Relationship {
	return {
		id: row.id,
		subjectType: row.subjectType,
		subjectId: row.subjectId,
		relation: row.relation,
		objectType: row.objectType,
		objectId: row.objectId,
		createdAt: row.createdAt,
	};
}
