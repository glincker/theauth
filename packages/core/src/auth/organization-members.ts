import { and, eq } from "drizzle-orm";
import { organizations, orgMembers, orgRoles } from "../db/schema.js";
import { makeMemberId, makeRoleId, rowToMember } from "./organization-helpers.js";
import type {
	Organization,
	OrgContext,
	OrgMember,
	OrgModule,
	OrgRole,
} from "./organization-types.js";

/** Membership, roles and permission checks for an organization. */
export function createOrgMembers(
	ctx: OrgContext & Pick<OrgModule, "get">,
): Pick<
	OrgModule,
	| "addMember"
	| "removeMember"
	| "updateMemberRole"
	| "getMembers"
	| "getMember"
	| "hasPermission"
	| "getRoles"
	| "createRole"
	| "removeRole"
	| "transferOwnership"
> {
	const { db, maxMembers, allowCustomRoles, get } = ctx;

	async function addMember(orgId: string, userId: string, role: string): Promise<OrgMember> {
		const org = await get(orgId);
		if (!org) throw new Error(`Organization "${orgId}" not found.`);

		const roleRows = await db
			.select()
			.from(orgRoles)
			.where(and(eq(orgRoles.orgId, orgId), eq(orgRoles.name, role)))
			.limit(1);
		if (roleRows.length === 0) throw new Error(`Role "${role}" does not exist in org "${orgId}".`);

		const currentMembers = await db
			.select({ id: orgMembers.id })
			.from(orgMembers)
			.where(eq(orgMembers.orgId, orgId));
		if (currentMembers.length >= maxMembers) {
			throw new Error(`Organization "${orgId}" has reached the maximum of ${maxMembers} members.`);
		}

		const already = await db
			.select()
			.from(orgMembers)
			.where(and(eq(orgMembers.orgId, orgId), eq(orgMembers.userId, userId)))
			.limit(1);
		if (already.length > 0) {
			throw new Error(`User "${userId}" is already a member of org "${orgId}".`);
		}

		const id = makeMemberId();
		const joinedAt = new Date();

		await db.insert(orgMembers).values({ id, orgId, userId, role, joinedAt });

		return { id, orgId, userId, role, joinedAt };
	}

	async function removeMember(orgId: string, userId: string): Promise<void> {
		// Prevent removing the last owner (would lock out the org)
		const member = await getMember(orgId, userId);
		if (member?.role === "owner") {
			const owners = await db
				.select({ id: orgMembers.id })
				.from(orgMembers)
				.where(and(eq(orgMembers.orgId, orgId), eq(orgMembers.role, "owner")));
			if (owners.length <= 1) {
				throw new Error(
					`Cannot remove the last owner of org "${orgId}". Transfer ownership first.`,
				);
			}
		}

		await db
			.delete(orgMembers)
			.where(and(eq(orgMembers.orgId, orgId), eq(orgMembers.userId, userId)));
	}

	async function updateMemberRole(orgId: string, userId: string, role: string): Promise<OrgMember> {
		const roleRows = await db
			.select()
			.from(orgRoles)
			.where(and(eq(orgRoles.orgId, orgId), eq(orgRoles.name, role)))
			.limit(1);
		if (roleRows.length === 0) throw new Error(`Role "${role}" does not exist in org "${orgId}".`);

		// Prevent demoting the last owner
		if (role !== "owner") {
			const currentMember = await getMember(orgId, userId);
			if (currentMember?.role === "owner") {
				const owners = await db
					.select({ id: orgMembers.id })
					.from(orgMembers)
					.where(and(eq(orgMembers.orgId, orgId), eq(orgMembers.role, "owner")));
				if (owners.length <= 1) {
					throw new Error(
						`Cannot demote the last owner of org "${orgId}". Transfer ownership first.`,
					);
				}
			}
		}

		await db
			.update(orgMembers)
			.set({ role })
			.where(and(eq(orgMembers.orgId, orgId), eq(orgMembers.userId, userId)));

		const member = await getMember(orgId, userId);
		if (!member) throw new Error(`Member "${userId}" not found in org "${orgId}".`);
		return member;
	}

	async function getMembers(orgId: string): Promise<OrgMember[]> {
		const rows = await db.select().from(orgMembers).where(eq(orgMembers.orgId, orgId));
		return rows.map(rowToMember);
	}

	async function getMember(orgId: string, userId: string): Promise<OrgMember | null> {
		const rows = await db
			.select()
			.from(orgMembers)
			.where(and(eq(orgMembers.orgId, orgId), eq(orgMembers.userId, userId)))
			.limit(1);
		const row = rows[0];
		if (!row) return null;
		return rowToMember(row);
	}

	async function hasPermission(
		orgId: string,
		userId: string,
		permission: string,
	): Promise<boolean> {
		const member = await getMember(orgId, userId);
		if (!member) return false;

		if (member.role === "owner") return true;

		const roleRows = await db
			.select()
			.from(orgRoles)
			.where(and(eq(orgRoles.orgId, orgId), eq(orgRoles.name, member.role)))
			.limit(1);
		const roleRow = roleRows[0];
		if (!roleRow) return false;

		return (roleRow.permissions as string[]).includes(permission);
	}

	async function getRoles(orgId: string): Promise<OrgRole[]> {
		const rows = await db.select().from(orgRoles).where(eq(orgRoles.orgId, orgId));
		return rows.map((r) => ({
			name: r.name,
			permissions: r.permissions as string[],
		}));
	}

	async function createRole(orgId: string, role: OrgRole): Promise<OrgRole> {
		if (!allowCustomRoles) {
			throw new Error("Custom roles are not allowed in this configuration.");
		}

		const org = await get(orgId);
		if (!org) throw new Error(`Organization "${orgId}" not found.`);

		const existing = await db
			.select({ id: orgRoles.id })
			.from(orgRoles)
			.where(and(eq(orgRoles.orgId, orgId), eq(orgRoles.name, role.name)))
			.limit(1);
		if (existing.length > 0) {
			throw new Error(`Role "${role.name}" already exists in org "${orgId}".`);
		}

		await db.insert(orgRoles).values({
			id: makeRoleId(),
			orgId,
			name: role.name,
			permissions: role.permissions,
		});

		return role;
	}

	async function removeRole(orgId: string, roleName: string): Promise<void> {
		await db.delete(orgRoles).where(and(eq(orgRoles.orgId, orgId), eq(orgRoles.name, roleName)));
	}

	async function transferOwnership(
		orgId: string,
		currentOwnerId: string,
		newOwnerId: string,
	): Promise<Organization> {
		const org = await get(orgId);
		if (!org) throw new Error(`Organization "${orgId}" not found.`);

		if (org.ownerId !== currentOwnerId) {
			throw new Error(`User "${currentOwnerId}" is not the owner of org "${orgId}".`);
		}

		// New owner must be a member
		const newOwnerMember = await getMember(orgId, newOwnerId);
		if (!newOwnerMember) {
			throw new Error(`User "${newOwnerId}" is not a member of org "${orgId}".`);
		}

		const now = new Date();
		await db
			.update(organizations)
			.set({ ownerId: newOwnerId, updatedAt: now })
			.where(eq(organizations.id, orgId));

		// Promote new owner to "owner" role
		await db
			.update(orgMembers)
			.set({ role: "owner" })
			.where(and(eq(orgMembers.orgId, orgId), eq(orgMembers.userId, newOwnerId)));

		// Demote current owner to "admin" (they stay as a member)
		await db
			.update(orgMembers)
			.set({ role: "admin" })
			.where(and(eq(orgMembers.orgId, orgId), eq(orgMembers.userId, currentOwnerId)));

		const updated = await get(orgId);
		if (!updated) throw new Error(`Organization "${orgId}" disappeared after ownership transfer.`);
		return updated;
	}

	return {
		addMember,
		removeMember,
		updateMemberRole,
		getMembers,
		getMember,
		hasPermission,
		getRoles,
		createRole,
		removeRole,
		transferOwnership,
	};
}
