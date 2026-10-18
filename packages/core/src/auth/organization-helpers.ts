import { generateId } from "../crypto/web-crypto.js";
import type { Organization, OrgInvitation, OrgMember, OrgRole } from "./organization-types.js";

// Defaults

export const DEFAULT_ROLES: OrgRole[] = [
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

export const DEFAULT_MAX_MEMBERS = 100;
export const DEFAULT_MAX_ORGS_PER_USER = 5;
export const INVITATION_EXPIRY_MS = 7 * 24 * 60 * 60 * 1000; // 7 days
export const DEFAULT_MAX_INVITATIONS_PER_HOUR = 50;

export function slugRegex(): RegExp {
	return /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
}

export function makeOrgId(): string {
	return `org_${generateId().replace(/-/g, "")}`;
}

export function makeMemberId(): string {
	return `mem_${generateId().replace(/-/g, "")}`;
}

export function makeInvId(): string {
	return `inv_${generateId().replace(/-/g, "")}`;
}

export function makeRoleId(): string {
	return `rol_${generateId().replace(/-/g, "")}`;
}

export function rowToOrg(row: {
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

export function rowToMember(row: {
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

export function rowToInvitation(row: {
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

export function jsonResponse(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "Content-Type": "application/json" },
	});
}

export function errorResponse(message: string, status: number): Response {
	return jsonResponse({ error: message }, status);
}
