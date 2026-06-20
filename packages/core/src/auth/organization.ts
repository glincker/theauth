/**
 * Organizations + RBAC module for TheAuth.
 *
 * Provides organization CRUD, membership management, invitation flows,
 * and role-based permission checking. Uses the kavach_organizations,
 * kavach_org_members, kavach_org_invitations, and kavach_org_roles tables.
 */

import { and, eq } from "drizzle-orm";
import { generateId } from "../crypto/web-crypto.js";
import type { Database } from "../db/database.js";
import { organizations, orgInvitations, orgMembers, orgRoles } from "../db/schema.js";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface OrgConfig {
	/** Default roles for new organizations */
	defaultRoles?: OrgRole[];
	/** Max members per org (default: 100) */
	maxMembers?: number;
	/** Max orgs a user can create (default: 5) */
	maxOrgsPerUser?: number;
	/** Allow custom roles (default: true) */
	allowCustomRoles?: boolean;
	/** Invitation expiry in milliseconds (default: 7 days) */
	invitationExpiryMs?: number;
	/** Max pending invitations per org per hour (default: 50) */
	maxInvitationsPerHour?: number;
}

export interface Organization {
	id: string;
	name: string;
	slug: string;
	ownerId: string;
	metadata?: Record<string, unknown>;
	createdAt: Date;
	updatedAt: Date;
}

export interface OrgMember {
	id: string;
	orgId: string;
	userId: string;
	role: string;
	joinedAt: Date;
}

export interface OrgRole {
	name: string;
	permissions: string[];
}

export interface OrgInvitation {
	id: string;
	orgId: string;
	email: string;
	role: string;
	invitedBy: string;
	status: "pending" | "accepted" | "expired";
	expiresAt: Date;
	createdAt: Date;
}

export interface OrgModule {
	create: (input: {
		name: string;
		slug: string;
		ownerId: string;
		metadata?: Record<string, unknown>;
	}) => Promise<Organization>;
	get: (orgId: string) => Promise<Organization | null>;
	getBySlug: (slug: string) => Promise<Organization | null>;
	list: (userId: string) => Promise<Organization[]>;
	update: (
		orgId: string,
		input: { name?: string; metadata?: Record<string, unknown> },
	) => Promise<Organization>;
	remove: (orgId: string) => Promise<void>;

	addMember: (orgId: string, userId: string, role: string) => Promise<OrgMember>;
	removeMember: (orgId: string, userId: string) => Promise<void>;
	updateMemberRole: (orgId: string, userId: string, role: string) => Promise<OrgMember>;
	getMembers: (orgId: string) => Promise<OrgMember[]>;
	getMember: (orgId: string, userId: string) => Promise<OrgMember | null>;

	invite: (input: {
		orgId: string;
		email: string;
		role: string;
		invitedBy: string;
	}) => Promise<OrgInvitation>;
	acceptInvitation: (invitationId: string, userId: string) => Promise<OrgMember>;
	listInvitations: (orgId: string) => Promise<OrgInvitation[]>;
	revokeInvitation: (invitationId: string) => Promise<void>;

	hasPermission: (orgId: string, userId: string, permission: string) => Promise<boolean>;
	getRoles: (orgId: string) => Promise<OrgRole[]>;
	createRole: (orgId: string, role: OrgRole) => Promise<OrgRole>;
	removeRole: (orgId: string, roleName: string) => Promise<void>;

	transferOwnership: (
		orgId: string,
		currentOwnerId: string,
		newOwnerId: string,
	) => Promise<Organization>;
	declineInvitation: (invitationId: string) => Promise<void>;

	handleRequest: (request: Request) => Promise<Response | null>;
}

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

const DEFAULT_ROLES: OrgRole[] = [
	{
		name: "owner",
		permissions: [
			"org:manage",
			"org:delete",
			"members:invite",
			"members:remove",
			"members:roles",
			"agents:create",
			"agents:revoke",
			"agents:manage",
			"roles:manage",
		],
	},
	{
		name: "admin",
		permissions: [
			"members:invite",
			"members:remove",
			"agents:create",
			"agents:revoke",
			"agents:manage",
		],
	},
	{
		name: "member",
		permissions: ["agents:create", "agents:manage"],
	},
	{
		name: "viewer",
		permissions: [],
	},
];

const DEFAULT_MAX_MEMBERS = 100;
const DEFAULT_MAX_ORGS_PER_USER = 5;
const INVITATION_EXPIRY_MS = 7 * 24 * 60 * 60 * 1000; // 7 days
const DEFAULT_MAX_INVITATIONS_PER_HOUR = 50;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function slugRegex(): RegExp {
	return /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
}

function makeOrgId(): string {
	return `org_${generateId().replace(/-/g, "")}`;
}

function makeMemberId(): string {
	return `mem_${generateId().replace(/-/g, "")}`;
}

function makeInvId(): string {
	return `inv_${generateId().replace(/-/g, "")}`;
}

function makeRoleId(): string {
	return `rol_${generateId().replace(/-/g, "")}`;
}

function rowToOrg(row: {
	id: string;
	name: string;
	slug: string;
	ownerId: string;
	metadata: Record<string, unknown> | null;
	createdAt: Date;
	updatedAt: Date;
}): Organization {
	return {
		id: row.id,
		name: row.name,
		slug: row.slug,
		ownerId: row.ownerId,
		metadata: row.metadata ?? undefined,
		createdAt: row.createdAt,
		updatedAt: row.updatedAt,
	};
}

function rowToMember(row: {
	id: string;
	orgId: string;
	userId: string;
	role: string;
	joinedAt: Date;
}): OrgMember {
	return {
		id: row.id,
		orgId: row.orgId,
		userId: row.userId,
		role: row.role,
		joinedAt: row.joinedAt,
	};
}

function rowToInvitation(row: {
	id: string;
	orgId: string;
	email: string;
	role: string;
	invitedBy: string;
	status: string;
	expiresAt: Date;
	createdAt: Date;
}): OrgInvitation {
	return {
		id: row.id,
		orgId: row.orgId,
		email: row.email,
		role: row.role,
		invitedBy: row.invitedBy,
		status: row.status as OrgInvitation["status"],
		expiresAt: row.expiresAt,
		createdAt: row.createdAt,
	};
}

function jsonResponse(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "Content-Type": "application/json" },
	});
}

function errorResponse(message: string, status: number): Response {
	return jsonResponse({ error: message }, status);
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

export function createOrgModule(config: OrgConfig, db: Database): OrgModule {
	const maxMembers = config.maxMembers ?? DEFAULT_MAX_MEMBERS;
	const maxOrgsPerUser = config.maxOrgsPerUser ?? DEFAULT_MAX_ORGS_PER_USER;
	const allowCustomRoles = config.allowCustomRoles ?? true;
	const defaultRoles = config.defaultRoles ?? DEFAULT_ROLES;
	const invitationExpiryMs = config.invitationExpiryMs ?? INVITATION_EXPIRY_MS;
	const maxInvitationsPerHour = config.maxInvitationsPerHour ?? DEFAULT_MAX_INVITATIONS_PER_HOUR;

	// ── org CRUD ─────────────────────────────────────────────────────────────

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

		// Enforce maxOrgsPerUser
		const existing = await db
			.select({ id: organizations.id })
			.from(organizations)
			.where(eq(organizations.ownerId, input.ownerId));
		if (existing.length >= maxOrgsPerUser) {
			throw new Error(
				`User "${input.ownerId}" has reached the maximum of ${maxOrgsPerUser} organizations.`,
			);
		}

		// Slug uniqueness
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

		await db.insert(organizations).values({
			id,
			name: input.name,
			slug: input.slug,
			ownerId: input.ownerId,
			metadata: input.metadata ?? null,
			createdAt: now,
			updatedAt: now,
		});

		// Add owner as member with "owner" role
		await db.insert(orgMembers).values({
			id: makeMemberId(),
			orgId: id,
			userId: input.ownerId,
			role: "owner",
			joinedAt: now,
		});

		// Seed default roles
		for (const role of defaultRoles) {
			await db.insert(orgRoles).values({
				id: makeRoleId(),
				orgId: id,
				name: role.name,
				permissions: role.permissions,
			});
		}

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

	// ── members ──────────────────────────────────────────────────────────────

	async function addMember(orgId: string, userId: string, role: string): Promise<OrgMember> {
		const org = await get(orgId);
		if (!org) throw new Error(`Organization "${orgId}" not found.`);

		// Validate role exists
		const roleRows = await db
			.select()
			.from(orgRoles)
			.where(and(eq(orgRoles.orgId, orgId), eq(orgRoles.name, role)))
			.limit(1);
		if (roleRows.length === 0) throw new Error(`Role "${role}" does not exist in org "${orgId}".`);

		// Check member cap
		const currentMembers = await db
			.select({ id: orgMembers.id })
			.from(orgMembers)
			.where(eq(orgMembers.orgId, orgId));
		if (currentMembers.length >= maxMembers) {
			throw new Error(`Organization "${orgId}" has reached the maximum of ${maxMembers} members.`);
		}

		// Check already a member
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
		// Validate role exists
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

	// ── invitations ──────────────────────────────────────────────────────────

	async function invite(input: {
		orgId: string;
		email: string;
		role: string;
		invitedBy: string;
	}): Promise<OrgInvitation> {
		const org = await get(input.orgId);
		if (!org) throw new Error(`Organization "${input.orgId}" not found.`);

		// Validate role exists
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

		// Mark accepted
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

	// ── roles & permissions ──────────────────────────────────────────────────

	async function hasPermission(
		orgId: string,
		userId: string,
		permission: string,
	): Promise<boolean> {
		const member = await getMember(orgId, userId);
		if (!member) return false;

		// Owner has all permissions
		if (member.role === "owner") return true;

		// Look up role permissions
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

		// Check for duplicate
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

	// ── ownership transfer ──────────────────────────────────────────────────

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

		// Update org owner
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

	// ── decline invitation ──────────────────────────────────────────────────

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

	// ── HTTP handler ─────────────────────────────────────────────────────────

	async function handleRequest(request: Request): Promise<Response | null> {
		const url = new URL(request.url);
		const { pathname } = url;
		const method = request.method.toUpperCase();

		// POST /auth/org
		if (method === "POST" && pathname === "/auth/org") {
			try {
				const body = (await request.json()) as {
					name: string;
					slug: string;
					ownerId: string;
					metadata?: Record<string, unknown>;
				};
				const org = await create(body);
				return jsonResponse(org, 201);
			} catch (err) {
				return errorResponse(err instanceof Error ? err.message : "Unknown error", 400);
			}
		}

		// GET /auth/org/user/:userId
		const userOrgMatch = pathname.match(/^\/auth\/org\/user\/([^/]+)$/);
		if (method === "GET" && userOrgMatch) {
			const userId = userOrgMatch[1];
			if (!userId) return errorResponse("Missing userId", 400);
			const orgs = await list(userId);
			return jsonResponse(orgs);
		}

		// Routes with orgId: /auth/org/:orgId or /auth/org/:orgId/...
		const orgBaseMatch = pathname.match(/^\/auth\/org\/([^/]+)(\/.*)?$/);
		if (!orgBaseMatch) return null;

		const orgId = orgBaseMatch[1];
		if (!orgId) return null;

		const subPath = orgBaseMatch[2] ?? "";

		// GET /auth/org/:orgId
		if (method === "GET" && subPath === "") {
			const org = await get(orgId);
			if (!org) return errorResponse("Organization not found", 404);
			return jsonResponse(org);
		}

		// PATCH /auth/org/:orgId
		if (method === "PATCH" && subPath === "") {
			try {
				const body = (await request.json()) as {
					name?: string;
					metadata?: Record<string, unknown>;
				};
				const org = await update(orgId, body);
				return jsonResponse(org);
			} catch (err) {
				return errorResponse(err instanceof Error ? err.message : "Unknown error", 400);
			}
		}

		// DELETE /auth/org/:orgId
		if (method === "DELETE" && subPath === "") {
			try {
				await remove(orgId);
				return jsonResponse({ success: true });
			} catch (err) {
				return errorResponse(err instanceof Error ? err.message : "Unknown error", 400);
			}
		}

		// POST /auth/org/:orgId/members
		if (method === "POST" && subPath === "/members") {
			try {
				const body = (await request.json()) as { userId: string; role: string };
				const member = await addMember(orgId, body.userId, body.role);
				return jsonResponse(member, 201);
			} catch (err) {
				return errorResponse(err instanceof Error ? err.message : "Unknown error", 400);
			}
		}

		// GET /auth/org/:orgId/members
		if (method === "GET" && subPath === "/members") {
			const members = await getMembers(orgId);
			return jsonResponse(members);
		}

		// PATCH /auth/org/:orgId/members/:userId
		const memberMatch = subPath.match(/^\/members\/([^/]+)$/);
		if (method === "PATCH" && memberMatch) {
			const userId = memberMatch[1];
			if (!userId) return errorResponse("Missing userId", 400);
			try {
				const body = (await request.json()) as { role: string };
				const member = await updateMemberRole(orgId, userId, body.role);
				return jsonResponse(member);
			} catch (err) {
				return errorResponse(err instanceof Error ? err.message : "Unknown error", 400);
			}
		}

		// DELETE /auth/org/:orgId/members/:userId
		if (method === "DELETE" && memberMatch) {
			const userId = memberMatch[1];
			if (!userId) return errorResponse("Missing userId", 400);
			await removeMember(orgId, userId);
			return jsonResponse({ success: true });
		}

		// POST /auth/org/:orgId/invite
		if (method === "POST" && subPath === "/invite") {
			try {
				const body = (await request.json()) as {
					email: string;
					role: string;
					invitedBy: string;
				};
				const invitation = await invite({ orgId, ...body });
				return jsonResponse(invitation, 201);
			} catch (err) {
				return errorResponse(err instanceof Error ? err.message : "Unknown error", 400);
			}
		}

		// GET /auth/org/:orgId/invitations
		if (method === "GET" && subPath === "/invitations") {
			const invitations = await listInvitations(orgId);
			return jsonResponse(invitations);
		}

		// GET /auth/org/:orgId/permissions/:userId/:permission
		const permMatch = subPath.match(/^\/permissions\/([^/]+)\/([^/]+)$/);
		if (method === "GET" && permMatch) {
			const userId = permMatch[1];
			const permission = permMatch[2];
			if (!userId || !permission) return errorResponse("Missing userId or permission", 400);
			const allowed = await hasPermission(orgId, userId, permission);
			return jsonResponse({ allowed });
		}

		// POST /auth/org/:orgId/roles
		if (method === "POST" && subPath === "/roles") {
			try {
				const body = (await request.json()) as OrgRole;
				const role = await createRole(orgId, body);
				return jsonResponse(role, 201);
			} catch (err) {
				return errorResponse(err instanceof Error ? err.message : "Unknown error", 400);
			}
		}

		// GET /auth/org/:orgId/roles
		if (method === "GET" && subPath === "/roles") {
			const roles = await getRoles(orgId);
			return jsonResponse(roles);
		}

		return null;
	}

	// POST /auth/org/invite/:invitationId/accept and DELETE /auth/org/invite/:invitationId
	// are matched inside handleRequest via a secondary pass when orgId catches "invite"
	// We need a top-level check before the orgId route for invite-specific paths.

	async function handleRequestWithInviteRoutes(request: Request): Promise<Response | null> {
		const url = new URL(request.url);
		const { pathname } = url;
		const method = request.method.toUpperCase();

		// POST /auth/org/invite/:invitationId/accept
		const acceptMatch = pathname.match(/^\/auth\/org\/invite\/([^/]+)\/accept$/);
		if (method === "POST" && acceptMatch) {
			const invitationId = acceptMatch[1];
			if (!invitationId) return errorResponse("Missing invitationId", 400);
			try {
				const body = (await request.json()) as { userId: string };
				const member = await acceptInvitation(invitationId, body.userId);
				return jsonResponse(member, 201);
			} catch (err) {
				return errorResponse(err instanceof Error ? err.message : "Unknown error", 400);
			}
		}

		// DELETE /auth/org/invite/:invitationId
		const revokeMatch = pathname.match(/^\/auth\/org\/invite\/([^/]+)$/);
		if (method === "DELETE" && revokeMatch) {
			const invitationId = revokeMatch[1];
			if (!invitationId) return errorResponse("Missing invitationId", 400);
			await revokeInvitation(invitationId);
			return jsonResponse({ success: true });
		}

		return handleRequest(request);
	}

	return {
		create,
		get,
		getBySlug,
		list,
		update,
		remove,
		addMember,
		removeMember,
		updateMemberRole,
		getMembers,
		getMember,
		invite,
		acceptInvitation,
		listInvitations,
		revokeInvitation,
		hasPermission,
		getRoles,
		createRole,
		removeRole,
		transferOwnership,
		declineInvitation,
		handleRequest: handleRequestWithInviteRoutes,
	};
}
