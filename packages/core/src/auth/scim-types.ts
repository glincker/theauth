import type { Database } from "../db/database.js";

export interface ScimConfig {
	bearerToken: string;
	/** Whether to auto-create users on provision (default: true) */
	autoCreateUsers?: boolean;
	/** Whether to auto-deactivate users on deprovision (default: true) */
	autoDeactivateUsers?: boolean;
	onProvision?: (user: ScimUser) => Promise<void>;
	onDeprovision?: (userId: string) => Promise<void>;
	/** Resolves the user id a request speaks for. Required for `GET /scim/v2/Me`; without it, `/Me` returns 501. */
	resolveSelf?: (request: Request) => Promise<string | null>;
	/**
	 * Audit every SCIM provisioning write. When configured, each POST/PUT/PATCH/DELETE on /Users or /Groups writes an `auditLogs` row attributed to `agentId`. The caller is responsible for pre-creating a system agent and passing its id. Set `enabled: false` to turn off writes without deleting the agent (useful in tests).
	 */
	audit?: {
		/** FK to kavach_agents.id, typically a dedicated "scim-provisioner" system agent. */
		agentId: string;
		/** Defaults to true when `audit` is set. */
		enabled?: boolean;
	};
}

export interface ScimUser {
	id: string;
	userName: string;
	name?: { givenName?: string; familyName?: string };
	emails?: Array<{ value: string; primary?: boolean }>;
	active?: boolean;
	externalId?: string;
}

export interface ScimGroup {
	id: string;
	displayName: string;
	externalId?: string;
	members?: Array<{ value: string; display?: string }>;
}

export interface ScimModule {
	handleRequest(request: Request): Promise<Response | null>;
}

export interface UserRow {
	id: string;
	email: string;
	name: string | null;
	username: string | null;
	externalId: string | null;
	externalProvider: string | null;
	banned: number;
	metadata: Record<string, unknown> | null;
	createdAt: Date;
	updatedAt: Date;
}

export interface OrgRow {
	id: string;
	name: string;
	slug: string;
	ownerId: string;
	metadata: Record<string, unknown> | null;
	createdAt: Date;
	updatedAt: Date;
}

export interface OrgMemberRow {
	id: string;
	orgId: string;
	userId: string;
	role: string;
	joinedAt: Date;
}

export interface PatchOperation {
	op: "add" | "replace" | "remove";
	path?: string;
	value?: unknown;
}

export interface PatchBody {
	schemas: string[];
	Operations: PatchOperation[];
}

/** Shared dependencies passed from createScimModule to the handler factories. */
export interface ScimHandlerContext {
	db: Database;
	config: ScimConfig;
	writeScimAudit: (
		action: string,
		resource: string,
		subjectUserId: string,
		durationMs: number,
		result?: "allowed" | "denied",
		reason?: string,
	) => Promise<void>;
}
