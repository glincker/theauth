import { eq } from "drizzle-orm";
import { organizations, orgInvitations, orgMembers, orgRoles } from "../db/schema.js";
import { createDrizzleKernel } from "../db/store/drizzle-kernel.js";
import type { WriteOp } from "../db/store/types.js";
import {
	makeMemberId,
	makeOrgId,
	makeRoleId,
	rowToOrg,
	slugRegex,
} from "./organization-helpers.js";
import type { Organization, OrgContext, OrgModule } from "./organization-types.js";

/** Organization CRUD: create, read, update and delete. */
export function createOrgCore(
	ctx: OrgContext,
): Pick<OrgModule, "create" | "get" | "getBySlug" | "list" | "update" | "remove"> {
	const { db, maxOrgsPerUser, defaultRoles } = ctx;

	async function create(input: {
		name: string;
		slug: string;
		ownerId: string;
		metadata?: Record<string, unknown>;
	}): Promise<Organization> {
		if (!slugRegex().test(input.slug)) {
			throw new Error(
				`Invalid slug "${input.slug}". Use lowercase letters, numbers, and hyphens only.`,
			);
		}

		const existing = await db
			.select({ id: organizations.id })
			.from(organizations)
			.where(eq(organizations.ownerId, input.ownerId));
		if (existing.length >= maxOrgsPerUser) {
			throw new Error(
				`User "${input.ownerId}" has reached the maximum of ${maxOrgsPerUser} organizations.`,
			);
		}

		const slugConflict = await db
			.select({ id: organizations.id })
			.from(organizations)
			.where(eq(organizations.slug, input.slug))
			.limit(1);
		if (slugConflict.length > 0) {
			throw new Error(`Organization with slug "${input.slug}" already exists.`);
		}

		const id = makeOrgId();
		const now = new Date();

		// One atomic group: an org never exists without its owner member and seeded roles.
		await createDrizzleKernel(db).batch([
			{
				op: "insert",
				model: "organizations",
				row: {
					id,
					name: input.name,
					slug: input.slug,
					ownerId: input.ownerId,
					metadata: input.metadata ?? null,
					createdAt: now,
					updatedAt: now,
				},
			},
			{
				op: "insert",
				model: "orgMembers",
				row: { id: makeMemberId(), orgId: id, userId: input.ownerId, role: "owner", joinedAt: now },
			},
			...defaultRoles.map(
				(role): WriteOp => ({
					op: "insert",
					model: "orgRoles",
					row: { id: makeRoleId(), orgId: id, name: role.name, permissions: role.permissions },
				}),
			),
		]);

		return {
			id,
			name: input.name,
			slug: input.slug,
			ownerId: input.ownerId,
			metadata: input.metadata,
			createdAt: now,
			updatedAt: now,
		};
	}

	async function get(orgId: string): Promise<Organization | null> {
		const rows = await db.select().from(organizations).where(eq(organizations.id, orgId)).limit(1);
		const row = rows[0];
		if (!row) return null;
		return rowToOrg(row);
	}

	async function getBySlug(slug: string): Promise<Organization | null> {
		const rows = await db.select().from(organizations).where(eq(organizations.slug, slug)).limit(1);
		const row = rows[0];
		if (!row) return null;
		return rowToOrg(row);
	}

	async function list(userId: string): Promise<Organization[]> {
		// Get all orgs the user is a member of
		const memberRows = await db
			.select({ orgId: orgMembers.orgId })
			.from(orgMembers)
			.where(eq(orgMembers.userId, userId));

		if (memberRows.length === 0) return [];

		const orgIds = memberRows.map((r) => r.orgId);
		const allOrgs = await db.select().from(organizations);
		return allOrgs.filter((org) => orgIds.includes(org.id)).map(rowToOrg);
	}

	async function update(
		orgId: string,
		input: { name?: string; metadata?: Record<string, unknown> },
	): Promise<Organization> {
		const existing = await get(orgId);
		if (!existing) throw new Error(`Organization "${orgId}" not found.`);

		const now = new Date();
		await db
			.update(organizations)
			.set({
				name: input.name ?? existing.name,
				metadata:
					input.metadata !== undefined
						? { ...(existing.metadata ?? {}), ...input.metadata }
						: (existing.metadata ?? null),
				updatedAt: now,
			})
			.where(eq(organizations.id, orgId));

		const updated = await get(orgId);
		if (!updated) throw new Error(`Organization "${orgId}" disappeared after update.`);
		return updated;
	}

	async function remove(orgId: string): Promise<void> {
		const existing = await get(orgId);
		if (!existing) throw new Error(`Organization "${orgId}" not found.`);
		// Explicit cascade: remove members, invitations, and roles before the org
		// (FK ON DELETE CASCADE may not be enabled in all SQLite configs)
		await db.delete(orgMembers).where(eq(orgMembers.orgId, orgId));
		await db.delete(orgInvitations).where(eq(orgInvitations.orgId, orgId));
		await db.delete(orgRoles).where(eq(orgRoles.orgId, orgId));
		await db.delete(organizations).where(eq(organizations.id, orgId));
	}

	return {
		create,
		get,
		getBySlug,
		list,
		update,
		remove,
	};
}
