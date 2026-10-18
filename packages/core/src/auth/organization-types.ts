import type { Database } from "../db/database.js";

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

/** Shared dependencies passed to the organization sub-modules. */
export interface OrgContext {
	db: Database;
	maxMembers: number;
	maxOrgsPerUser: number;
	allowCustomRoles: boolean;
	defaultRoles: OrgRole[];
	invitationExpiryMs: number;
	maxInvitationsPerHour: number;
}
