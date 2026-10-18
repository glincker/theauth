/** Organizations + RBAC module for TheAuth. */

import type { Database } from "../db/database.js";
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

export type {
	Organization,
	OrgConfig,
	OrgInvitation,
	OrgMember,
	OrgModule,
	OrgRole,
} from "./organization-types.js";

export function createOrgModule(config: OrgConfig, db: Database): OrgModule {
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
	const handlers = createOrgHandlers({ ...core, ...members, ...invitations });

	return { ...core, ...members, ...invitations, ...handlers };
}
