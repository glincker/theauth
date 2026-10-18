import { and, eq } from "drizzle-orm";
import { orgInvitations, orgRoles } from "../db/schema.js";
import { makeInvId, rowToInvitation } from "./organization-helpers.js";
import type { OrgContext, OrgInvitation, OrgMember, OrgModule } from "./organization-types.js";

/** Invitation lifecycle: invite, accept, decline, revoke and list. */
export function createOrgInvitations(
	ctx: OrgContext & Pick<OrgModule, "get" | "addMember">,
): Pick<
	OrgModule,
	"invite" | "acceptInvitation" | "listInvitations" | "revokeInvitation" | "declineInvitation"
> {
	const { db, invitationExpiryMs, maxInvitationsPerHour, get, addMember } = ctx;

	async function invite(input: {
		orgId: string;
		email: string;
		role: string;
		invitedBy: string;
	}): Promise<OrgInvitation> {
		const org = await get(input.orgId);
		if (!org) throw new Error(`Organization "${input.orgId}" not found.`);

		const roleRows = await db
			.select()
			.from(orgRoles)
			.where(and(eq(orgRoles.orgId, input.orgId), eq(orgRoles.name, input.role)))
			.limit(1);
		if (roleRows.length === 0) {
			throw new Error(`Role "${input.role}" does not exist in org "${input.orgId}".`);
		}

		// Reject duplicate pending invitation for the same email in this org
		const duplicateInvite = await db
			.select({ id: orgInvitations.id })
			.from(orgInvitations)
			.where(
				and(
					eq(orgInvitations.orgId, input.orgId),
					eq(orgInvitations.email, input.email),
					eq(orgInvitations.status, "pending"),
				),
			)
			.limit(1);
		if (duplicateInvite.length > 0) {
			throw new Error(
				`A pending invitation for "${input.email}" already exists in org "${input.orgId}".`,
			);
		}

		// Rate limit: max invitations per hour per org
		const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
		const allOrgInvites = await db
			.select({ id: orgInvitations.id, createdAt: orgInvitations.createdAt })
			.from(orgInvitations)
			.where(eq(orgInvitations.orgId, input.orgId));
		const recentInviteCount = allOrgInvites.filter((inv) => inv.createdAt >= oneHourAgo).length;
		if (recentInviteCount >= maxInvitationsPerHour) {
			throw new Error(
				`Invitation rate limit reached for org "${input.orgId}". Max ${maxInvitationsPerHour} per hour.`,
			);
		}

		const id = makeInvId();
		const now = new Date();
		const expiresAt = new Date(now.getTime() + invitationExpiryMs);

		await db.insert(orgInvitations).values({
			id,
			orgId: input.orgId,
			email: input.email,
			role: input.role,
			invitedBy: input.invitedBy,
			status: "pending",
			expiresAt,
			createdAt: now,
		});

		return {
			id,
			orgId: input.orgId,
			email: input.email,
			role: input.role,
			invitedBy: input.invitedBy,
			status: "pending",
			expiresAt,
			createdAt: now,
		};
	}

	async function acceptInvitation(invitationId: string, userId: string): Promise<OrgMember> {
		const rows = await db
			.select()
			.from(orgInvitations)
			.where(eq(orgInvitations.id, invitationId))
			.limit(1);
		const inv = rows[0];
		if (!inv) throw new Error(`Invitation "${invitationId}" not found.`);

		if (inv.status !== "pending") {
			throw new Error(`Invitation "${invitationId}" is not pending (status: ${inv.status}).`);
		}

		const now = new Date();
		if (inv.expiresAt < now) {
			// Mark expired in DB
			await db
				.update(orgInvitations)
				.set({ status: "expired" })
				.where(eq(orgInvitations.id, invitationId));
			throw new Error(`Invitation "${invitationId}" has expired.`);
		}

		// Add member (will throw if already a member or cap hit)
		const member = await addMember(inv.orgId, userId, inv.role);

		await db
			.update(orgInvitations)
			.set({ status: "accepted" })
			.where(eq(orgInvitations.id, invitationId));

		return member;
	}

	async function listInvitations(orgId: string): Promise<OrgInvitation[]> {
		const rows = await db.select().from(orgInvitations).where(eq(orgInvitations.orgId, orgId));
		return rows.map(rowToInvitation);
	}

	async function revokeInvitation(invitationId: string): Promise<void> {
		await db.delete(orgInvitations).where(eq(orgInvitations.id, invitationId));
	}

	async function declineInvitation(invitationId: string): Promise<void> {
		const rows = await db
			.select()
			.from(orgInvitations)
			.where(eq(orgInvitations.id, invitationId))
			.limit(1);
		const inv = rows[0];
		if (!inv) throw new Error(`Invitation "${invitationId}" not found.`);
		if (inv.status !== "pending") {
			throw new Error(`Invitation "${invitationId}" is not pending (status: ${inv.status}).`);
		}
		// Delete the invitation (one-time use: no need to keep declined invitations)
		await db.delete(orgInvitations).where(eq(orgInvitations.id, invitationId));
	}

	return {
		invite,
		acceptInvitation,
		listInvitations,
		revokeInvitation,
		declineInvitation,
	};
}
