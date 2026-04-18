/**
 * Template 06, ReBAC document sharing (friends-of-a-friend)
 *
 * Access to a document is controlled by graph tuples, not static rows.
 * The permission row carries a `relation` field. The engine calls the ReBAC
 * bridge to check whether the subject holds that relation on the requested
 * resource. If the tuple exists, access is granted.
 *
 * IMPORTANT, wildcard limitation:
 * The ReBAC bridge (rebac-bridge.ts) rejects resources that contain "*"
 * (wildcard IDs). It returns matched=false with reason
 * "rebac:wildcard-resource-not-supported". Always use concrete document IDs
 * such as "doc:42" rather than "doc:*". See the README for details.
 *
 * Seeding steps:
 *   1. Insert the permission row below into kavach_permissions.
 *   2. Create the resource in kavach_rebac_resources:
 *        { id: "42", type: "doc" }
 *   3. Add a relationship tuple in kavach_rebac_relationships:
 *        { subjectType: "agent", subjectId: <agentId>,
 *          relation: "viewer", objectType: "doc", objectId: "42" }
 */

import type { Permission } from "../../../../packages/core/src/types.js";

/**
 * Permission row for document access. The resource must be a concrete ID ,
 * replace "42" with the actual document ID you want to protect.
 */
export const rebacDocPermission: Permission[] = [
	{
		resource: "doc:42",
		actions: ["read"],
		relation: "viewer",
	},
];
