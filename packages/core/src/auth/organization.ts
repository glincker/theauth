/** Organizations + RBAC module for TheAuth. */

import { eq } from "drizzle-orm";
import type { Database } from "../db/database.js";
import { orgInvitations, users } from "../db/schema.js";
import { createOrgCore } from "./organization-core.js";
import { createOrgHandlers } from "./organization-handlers.js";
import {
	DEFAULT_MAX_INVITATIONS_PER_HOUR,
	DEFAULT_MAX_MEMBERS,
	DEFAULT_MAX_ORGS_PER_USER,
	DEFAULT_ROLES,
	INVITATION_EXPIRY_MS,
} from "./organization-helpers.js";
import { createOrgInvitations } from "./organization-invitations.js";
import { createOrgMembers } from "./organization-members.js";
import type { OrgConfig, OrgContext, OrgModule } from "./organization-types.js";
import type { ModuleRequestDeps } from "./request-user.js";

export type {
	Organization,
	OrgConfig,
	OrgInvitation,
	OrgMember,
	OrgModule,
	OrgRole,
} from "./organization-types.js";

export function createOrgModule(
	config: OrgConfig,
	db: Database,
	deps: ModuleRequestDeps = {},
): OrgModule {
	const maxMembers = config.maxMembers ?? DEFAULT_MAX_MEMBERS;
	const maxOrgsPerUser = config.maxOrgsPerUser ?? DEFAULT_MAX_ORGS_PER_USER;
	const allowCustomRoles = config.allowCustomRoles ?? true;
	const defaultRoles = config.defaultRoles ?? DEFAULT_ROLES;
	const invitationExpiryMs = config.invitationExpiryMs ?? INVITATION_EXPIRY_MS;
	const maxInvitationsPerHour = config.maxInvitationsPerHour ?? DEFAULT_MAX_INVITATIONS_PER_HOUR;

	const ctx: OrgContext = {
		db,
		maxMembers,
		maxOrgsPerUser,
		allowCustomRoles,
		defaultRoles,
		invitationExpiryMs,
		maxInvitationsPerHour,
	};
	const core = createOrgCore(ctx);
	const members = createOrgMembers({ ...ctx, get: core.get });
	const invitations = createOrgInvitations({ ...ctx, get: core.get, addMember: members.addMember });
	const handlers = createOrgHandlers(
		{ ...core, ...members, ...invitations },
		{
			deps,
			config,
			invitationOf: async (invitationId) => {
				const rows = await db
					.select({ orgId: orgInvitations.orgId, email: orgInvitations.email })
					.from(orgInvitations)
					.where(eq(orgInvitations.id, invitationId))
					.limit(1);
				return rows[0] ?? null;
			},
			userEmail: async (userId) => {
				const rows = await db
					.select({ email: users.email })
					.from(users)
					.where(eq(users.id, userId))
					.limit(1);
				return rows[0]?.email ?? null;
			},
		},
	);

	return { ...core, ...members, ...invitations, ...handlers };
}
