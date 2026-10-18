import type { Result } from "../mcp/types.js";

export interface ReBACConfig {
	/** Maximum graph traversal depth for permission checks (default: 10). */
	maxDepth?: number;
	/** Permission rules per resource type. Key is the resource type. */
	permissionRules?: Record<string, PermissionRuleSet>;
}

/** Defines how relations map to permissions for a given resource type. */
export interface PermissionRuleSet {
	/** Which relations imply which other relations on the same object. */
	implies?: Record<string, string[]>;
	/** Permissions inherited from the parent resource. `true` = all, or list. */
	inheritFromParent?: boolean | string[];
}

export interface ResourceNode {
	id: string;
	type: string;
	parentId?: string;
	parentType?: string;
}

export interface Relationship {
	id: string;
	subjectType: string;
	subjectId: string;
	relation: string;
	objectType: string;
	objectId: string;
	createdAt: Date;
}

export interface CheckParams {
	subjectType: string;
	subjectId: string;
	permission: string;
	objectType: string;
	objectId: string;
}

export interface CheckResult {
	allowed: boolean;
	path?: string[];
}

export interface ListObjectsParams {
	subjectType: string;
	subjectId: string;
	permission: string;
	objectType: string;
}

export interface ListSubjectsParams {
	objectType: string;
	objectId: string;
	permission: string;
	subjectType: string;
}

export interface ExpandParams {
	type: string;
	id: string;
}

export interface ReBACModule {
	/** Register a resource in the hierarchy. */
	createResource(node: ResourceNode): Promise<Result<ResourceNode>>;
	/** Remove a resource and all its relationships. */
	deleteResource(type: string, id: string): Promise<Result<void>>;
	/** Get a resource by type and id. */
	getResource(type: string, id: string): Promise<Result<ResourceNode | null>>;

	/** Create a relationship between a subject and an object. */
	addRelationship(rel: Omit<Relationship, "id" | "createdAt">): Promise<Result<Relationship>>;
	/** Remove a specific relationship. */
	removeRelationship(
		subjectType: string,
		subjectId: string,
		relation: string,
		objectType: string,
		objectId: string,
	): Promise<Result<void>>;

	/** Check whether a subject has a permission on an object. Returns the relationship path when access is granted. */
	check(params: CheckParams): Promise<Result<CheckResult>>;

	/** List all object IDs of a given type that a subject can access with a permission. */
	listObjects(params: ListObjectsParams): Promise<Result<string[]>>;

	/** List all subject IDs of a given type that hold a permission on an object. */
	listSubjects(params: ListSubjectsParams): Promise<Result<string[]>>;

	/** Return all relationships where the given entity is subject or object. */
	expand(params: ExpandParams): Promise<Result<Relationship[]>>;
}

// Default permission rules
