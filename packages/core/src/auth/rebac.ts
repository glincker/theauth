/**
 * Relationship-Based Access Control (ReBAC) engine for TheAuth.
 *
 * Inspired by Google Zanzibar. Models authorization as a graph of typed
 * relationships between subjects (users, agents, teams) and objects
 * (orgs, workspaces, projects, documents). Permission checks traverse the
 * graph, following both direct relationships and parent-child inheritance.
 *
 * Key ideas:
 * - Resources live in a hierarchy (org > workspace > project > document).
 * - Relationships connect subjects to objects with a named relation.
 * - Permission rules define how relations compose. An "editor" implicitly
 *   has "viewer" access; a "viewer" on a workspace inherits "viewer" on
 *   child projects.
 * - Graph traversal is depth-limited to prevent runaway queries.
 */

import { and, eq, or } from "drizzle-orm";
import { generateId } from "../crypto/web-crypto.js";
import type { Database } from "../db/database.js";
import { rebacRelationships, rebacResources } from "../db/schema.js";
import type { Result } from "../mcp/types.js";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface ReBACConfig {
	/** Maximum graph traversal depth for permission checks (default: 10). */
	maxDepth?: number;
	/** Permission rules per resource type. Key is the resource type. */
	permissionRules?: Record<string, PermissionRuleSet>;
}

/**
 * Defines how relations map to permissions for a given resource type.
 *
 * `implies` — relation X implies relation Y (e.g. editor implies viewer).
 * `inherits` — permission P on this resource's parent also grants P here.
 */
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

	/**
	 * Check whether a subject has a permission on an object.
	 * Returns the relationship path when access is granted.
	 */
	check(params: CheckParams): Promise<Result<CheckResult>>;

	/** List all object IDs of a given type that a subject can access with a permission. */
	listObjects(params: ListObjectsParams): Promise<Result<string[]>>;

	/** List all subject IDs of a given type that hold a permission on an object. */
	listSubjects(params: ListSubjectsParams): Promise<Result<string[]>>;

	/** Return all relationships where the given entity is subject or object. */
	expand(params: ExpandParams): Promise<Result<Relationship[]>>;
}

// ---------------------------------------------------------------------------
// Default permission rules
// ---------------------------------------------------------------------------

const DEFAULT_PERMISSION_RULES: Record<string, PermissionRuleSet> = {
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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function ok<T>(data: T): Result<T> {
	return { success: true, data };
}

function fail<T>(code: string, message: string): Result<T> {
	return { success: false, error: { code, message } };
}

function rowToResource(row: {
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

function rowToRelationship(row: {
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

// ---------------------------------------------------------------------------
// Module factory
// ---------------------------------------------------------------------------

export function createReBACModule(config: ReBACConfig, db: Database): ReBACModule {
	const maxDepth = config.maxDepth ?? 10;
	const rules: Record<string, PermissionRuleSet> = {
		...DEFAULT_PERMISSION_RULES,
		...config.permissionRules,
	};

	// ── Helpers ────────────────────────────────────────────────────────────

	/**
	 * Get all relations that effectively grant `permission` on resource type
	 * `objectType`. E.g. asking for "viewer" on a "document" returns
	 * ["viewer", "editor", "owner"] because editor and owner imply viewer.
	 */
	function getGrantingRelations(objectType: string, permission: string): string[] {
		const ruleSet = rules[objectType];
		if (!ruleSet?.implies) return [permission];
		const granting = new Set<string>([permission]);
		// Walk the implies map: if relation R implies permission P, R grants P.
		for (const [relation, implied] of Object.entries(ruleSet.implies)) {
			if (implied.includes(permission)) {
				granting.add(relation);
			}
		}
		return [...granting];
	}

	/**
	 * Check whether permission is inherited from parent for a given type.
	 */
	function shouldInherit(objectType: string, permission: string): boolean {
		const ruleSet = rules[objectType];
		if (!ruleSet?.inheritFromParent) return false;
		if (ruleSet.inheritFromParent === true) return true;
		return ruleSet.inheritFromParent.includes(permission);
	}

	/**
	 * Recursively check access. Returns a path of readable steps if granted.
	 */
	async function checkAccess(
		subjectType: string,
		subjectId: string,
		permission: string,
		objectType: string,
		objectId: string,
		depth: number,
		visited: Set<string>,
	): Promise<CheckResult> {
		if (depth > maxDepth) {
			return { allowed: false };
		}

		const visitKey = `${objectType}:${objectId}:${permission}`;
		if (visited.has(visitKey)) {
			return { allowed: false };
		}
		visited.add(visitKey);

		// 1. Direct relationship check (including implied relations)
		const grantingRelations = getGrantingRelations(objectType, permission);
		for (const rel of grantingRelations) {
			const rows = await db
				.select()
				.from(rebacRelationships)
				.where(
					and(
						eq(rebacRelationships.subjectType, subjectType),
						eq(rebacRelationships.subjectId, subjectId),
						eq(rebacRelationships.relation, rel),
						eq(rebacRelationships.objectType, objectType),
						eq(rebacRelationships.objectId, objectId),
					),
				);
			if (rows.length > 0) {
				return {
					allowed: true,
					path: [`${subjectType}:${subjectId}#${rel}@${objectType}:${objectId}`],
				};
			}
		}

		// 2. Inheritance: check parent resource
		if (shouldInherit(objectType, permission)) {
			const resourceRows = await db
				.select()
				.from(rebacResources)
				.where(and(eq(rebacResources.id, objectId), eq(rebacResources.type, objectType)));
			const resource = resourceRows[0];
			if (resource?.parentId && resource.parentType) {
				const parentResult = await checkAccess(
					subjectType,
					subjectId,
					permission,
					resource.parentType,
					resource.parentId,
					depth + 1,
					visited,
				);
				if (parentResult.allowed) {
					return {
						allowed: true,
						path: [
							...(parentResult.path ?? []),
							`inherit:${resource.parentType}:${resource.parentId}->${objectType}:${objectId}`,
						],
					};
				}
			}
		}

		return { allowed: false };
	}

	// ── Public API ─────────────────────────────────────────────────────────

	const createResource: ReBACModule["createResource"] = async (node) => {
		// Validate parent exists if specified
		if (node.parentId && node.parentType) {
			const parentRows = await db
				.select()
				.from(rebacResources)
				.where(and(eq(rebacResources.id, node.parentId), eq(rebacResources.type, node.parentType)));
			if (parentRows.length === 0) {
				return fail(
					"PARENT_NOT_FOUND",
					`Parent resource ${node.parentType}:${node.parentId} not found`,
				);
			}
		}

		// Check for duplicates (id is the primary key)
		const existing = await db.select().from(rebacResources).where(eq(rebacResources.id, node.id));
		if (existing.length > 0) {
			return fail("RESOURCE_EXISTS", `Resource ${node.type}:${node.id} already exists`);
		}

		const now = new Date();
		await db.insert(rebacResources).values({
			id: node.id,
			type: node.type,
			parentId: node.parentId ?? null,
			parentType: node.parentType ?? null,
			createdAt: now,
		});

		return ok(node);
	};

	const deleteResource: ReBACModule["deleteResource"] = async (type, id) => {
		// Delete all relationships where this resource is subject or object
		const rows = await db
			.select()
			.from(rebacRelationships)
			.where(
				or(
					and(eq(rebacRelationships.objectType, type), eq(rebacRelationships.objectId, id)),
					and(eq(rebacRelationships.subjectType, type), eq(rebacRelationships.subjectId, id)),
				),
			);
		for (const row of rows) {
			await db.delete(rebacRelationships).where(eq(rebacRelationships.id, row.id));
		}

		// Delete child resources
		const children = await db
			.select()
			.from(rebacResources)
			.where(and(eq(rebacResources.parentId, id), eq(rebacResources.parentType, type)));
		for (const child of children) {
			await deleteResource(child.type, child.id);
		}

		// Delete the resource itself
		await db
			.delete(rebacResources)
			.where(and(eq(rebacResources.id, id), eq(rebacResources.type, type)));

		return ok(undefined);
	};

	const getResource: ReBACModule["getResource"] = async (type, id) => {
		const rows = await db
			.select()
			.from(rebacResources)
			.where(and(eq(rebacResources.id, id), eq(rebacResources.type, type)));
		if (rows.length === 0) return ok(null);
		const row = rows[0];
		if (!row) return ok(null);
		return ok(rowToResource(row));
	};

	const addRelationship: ReBACModule["addRelationship"] = async (rel) => {
		// Check for duplicate
		const existing = await db
			.select()
			.from(rebacRelationships)
			.where(
				and(
					eq(rebacRelationships.subjectType, rel.subjectType),
					eq(rebacRelationships.subjectId, rel.subjectId),
					eq(rebacRelationships.relation, rel.relation),
					eq(rebacRelationships.objectType, rel.objectType),
					eq(rebacRelationships.objectId, rel.objectId),
				),
			);
		if (existing.length > 0) {
			return fail(
				"RELATIONSHIP_EXISTS",
				`Relationship ${rel.subjectType}:${rel.subjectId}#${rel.relation}@${rel.objectType}:${rel.objectId} already exists`,
			);
		}

		const id = `rel_${generateId()}`;
		const now = new Date();
		await db.insert(rebacRelationships).values({
			id,
			subjectType: rel.subjectType,
			subjectId: rel.subjectId,
			relation: rel.relation,
			objectType: rel.objectType,
			objectId: rel.objectId,
			createdAt: now,
		});

		return ok({
			id,
			...rel,
			createdAt: now,
		});
	};

	const removeRelationship: ReBACModule["removeRelationship"] = async (
		subjectType,
		subjectId,
		relation,
		objectType,
		objectId,
	) => {
		await db
			.delete(rebacRelationships)
			.where(
				and(
					eq(rebacRelationships.subjectType, subjectType),
					eq(rebacRelationships.subjectId, subjectId),
					eq(rebacRelationships.relation, relation),
					eq(rebacRelationships.objectType, objectType),
					eq(rebacRelationships.objectId, objectId),
				),
			);
		return ok(undefined);
	};

	const check: ReBACModule["check"] = async (params) => {
		const result = await checkAccess(
			params.subjectType,
			params.subjectId,
			params.permission,
			params.objectType,
			params.objectId,
			0,
			new Set(),
		);
		return ok(result);
	};

	const listObjects: ReBACModule["listObjects"] = async (params) => {
		const grantingRelations = getGrantingRelations(params.objectType, params.permission);

		// Collect directly-related objects
		const objectIds = new Set<string>();

		for (const rel of grantingRelations) {
			const rows = await db
				.select()
				.from(rebacRelationships)
				.where(
					and(
						eq(rebacRelationships.subjectType, params.subjectType),
						eq(rebacRelationships.subjectId, params.subjectId),
						eq(rebacRelationships.relation, rel),
						eq(rebacRelationships.objectType, params.objectType),
					),
				);
			for (const row of rows) {
				objectIds.add(row.objectId);
			}
		}

		// Also find objects through parent inheritance
		if (shouldInherit(params.objectType, params.permission)) {
			// Get all resources of the target type that have parents
			const resources = await db
				.select()
				.from(rebacResources)
				.where(eq(rebacResources.type, params.objectType));

			for (const resource of resources) {
				if (objectIds.has(resource.id)) continue;
				if (!resource.parentId || !resource.parentType) continue;

				const result = await checkAccess(
					params.subjectType,
					params.subjectId,
					params.permission,
					params.objectType,
					resource.id,
					0,
					new Set(),
				);
				if (result.allowed) {
					objectIds.add(resource.id);
				}
			}
		}

		return ok([...objectIds]);
	};

	const listSubjects: ReBACModule["listSubjects"] = async (params) => {
		const grantingRelations = getGrantingRelations(params.objectType, params.permission);
		const subjectIds = new Set<string>();

		// Direct relationships on this object
		for (const rel of grantingRelations) {
			const rows = await db
				.select()
				.from(rebacRelationships)
				.where(
					and(
						eq(rebacRelationships.objectType, params.objectType),
						eq(rebacRelationships.objectId, params.objectId),
						eq(rebacRelationships.relation, rel),
						eq(rebacRelationships.subjectType, params.subjectType),
					),
				);
			for (const row of rows) {
				subjectIds.add(row.subjectId);
			}
		}

		// Subjects with access via parent inheritance
		if (shouldInherit(params.objectType, params.permission)) {
			const resourceRows = await db
				.select()
				.from(rebacResources)
				.where(
					and(eq(rebacResources.id, params.objectId), eq(rebacResources.type, params.objectType)),
				);
			const resource = resourceRows[0];
			if (resource?.parentId && resource.parentType) {
				const parentSubjects = await listSubjects({
					objectType: resource.parentType,
					objectId: resource.parentId,
					permission: params.permission,
					subjectType: params.subjectType,
				});
				if (parentSubjects.success) {
					for (const sid of parentSubjects.data) {
						subjectIds.add(sid);
					}
				}
			}
		}

		return ok([...subjectIds]);
	};

	const expand: ReBACModule["expand"] = async (params) => {
		const asSubject = await db
			.select()
			.from(rebacRelationships)
			.where(
				and(
					eq(rebacRelationships.subjectType, params.type),
					eq(rebacRelationships.subjectId, params.id),
				),
			);
		const asObject = await db
			.select()
			.from(rebacRelationships)
			.where(
				and(
					eq(rebacRelationships.objectType, params.type),
					eq(rebacRelationships.objectId, params.id),
				),
			);

		const all = [...asSubject, ...asObject].map(rowToRelationship);
		// Deduplicate by id
		const seen = new Set<string>();
		const unique: Relationship[] = [];
		for (const r of all) {
			if (!seen.has(r.id)) {
				seen.add(r.id);
				unique.push(r);
			}
		}

		return ok(unique);
	};

	return {
		createResource,
		deleteResource,
		getResource,
		addRelationship,
		removeRelationship,
		check,
		listObjects,
		listSubjects,
		expand,
	};
}
