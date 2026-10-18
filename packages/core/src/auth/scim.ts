/**
 * SCIM 2.0 directory sync (RFC 7644) for enterprise identity providers such as Okta, Azure AD and Google Workspace.
 *
 * @example
 * ```typescript
 * import { createScimModule } from '@glinr/theauth/auth';
 *
 * const scim = createScimModule({
 *   bearerToken: process.env.SCIM_TOKEN,
 *   onProvision: async (user) => {
 *     console.log('Provisioned:', user.userName);
 *   },
 * }, db);
 *
 * // In your request handler:
 * const response = await scim.handleRequest(request);
 * ```
 */

import { recordAuditEvent } from "../audit/record.js";
import type { Database } from "../db/database.js";
import type { RevocationBus } from "../mcp/revocation-bus.js";
import {
	handleBulk,
	handleResourceTypes,
	handleSchemas,
	handleServiceProviderConfig,
} from "./scim-discovery.js";
import { createScimGroupHandlers } from "./scim-groups.js";
import { extractId, scimError } from "./scim-helpers.js";
import type { ScimConfig, ScimHandlerContext, ScimModule } from "./scim-types.js";
import { createScimUserHandlers } from "./scim-users.js";

export type { ScimConfig, ScimGroup, ScimModule, ScimUser } from "./scim-types.js";

export function createScimModule(
	config: ScimConfig,
	db: Database,
	revocations?: RevocationBus | null,
): ScimModule {
	const { bearerToken, audit } = config;

	// Best-effort: a failed audit write must never fail the provisioning response.

	async function writeScimAudit(
		action: string,
		resource: string,
		subjectUserId: string,
		durationMs: number,
		result: "allowed" | "denied" = "allowed",
		reason?: string,
	): Promise<void> {
		if (!audit || audit.enabled === false) return;
		try {
			await recordAuditEvent(db, {
				agentId: audit.agentId,
				userId: subjectUserId,
				action,
				resource,
				parameters: {},
				result,
				reason,
				durationMs,
			});
		} catch {
			// Audit is best-effort. A missing system agent FK or a transient DB
			// error must not fail the SCIM request itself.
		}
	}

	function isAuthorized(request: Request): boolean {
		const authHeader = request.headers.get("Authorization");
		if (!authHeader) return false;
		const [scheme, token] = authHeader.split(" ");
		return scheme?.toLowerCase() === "bearer" && token === bearerToken;
	}
	const ctx: ScimHandlerContext = { db, config, writeScimAudit, revocations };
	const {
		handleListUsers,
		handleGetUser,
		handleCreateUser,
		handleReplaceUser,
		handlePatchUser,
		handleDeleteUser,
		handleMe,
	} = createScimUserHandlers(ctx);
	const {
		handleListGroups,
		handleGetGroup,
		handleCreateGroup,
		handleReplaceGroup,
		handlePatchGroup,
		handleDeleteGroup,
	} = createScimGroupHandlers(ctx);

	async function handleRequest(request: Request): Promise<Response | null> {
		const url = new URL(request.url);
		const pathname = url.pathname;

		if (!pathname.includes("/scim/v2/")) return null;

		if (!isAuthorized(request)) {
			return scimError("Unauthorized: valid Bearer token required", 401);
		}

		const method = request.method.toUpperCase();

		if (method === "GET" && pathname.endsWith("/scim/v2/ServiceProviderConfig")) {
			return handleServiceProviderConfig(request);
		}
		if (method === "GET" && pathname.endsWith("/scim/v2/Schemas")) {
			return handleSchemas(request);
		}
		if (method === "GET" && pathname.endsWith("/scim/v2/ResourceTypes")) {
			return handleResourceTypes(request);
		}
		if (method === "GET" && pathname.endsWith("/scim/v2/Me")) {
			return handleMe(request);
		}
		if (method === "POST" && pathname.endsWith("/scim/v2/Bulk")) {
			return handleBulk(request);
		}

		if (method === "GET" && /\/scim\/v2\/Users\/?$/.test(pathname)) {
			return handleListUsers(request);
		}
		if (method === "POST" && /\/scim\/v2\/Users\/?$/.test(pathname)) {
			return handleCreateUser(request);
		}

		const userId = extractId(pathname, "Users");
		if (userId) {
			if (method === "GET") return handleGetUser(request, userId);
			if (method === "PUT") return handleReplaceUser(request, userId);
			if (method === "PATCH") return handlePatchUser(request, userId);
			if (method === "DELETE") return handleDeleteUser(request, userId);
		}

		if (method === "GET" && /\/scim\/v2\/Groups\/?$/.test(pathname)) {
			return handleListGroups(request);
		}
		if (method === "POST" && /\/scim\/v2\/Groups\/?$/.test(pathname)) {
			return handleCreateGroup(request);
		}

		const groupId = extractId(pathname, "Groups");
		if (groupId) {
			if (method === "GET") return handleGetGroup(request, groupId);
			if (method === "PUT") return handleReplaceGroup(request, groupId);
			if (method === "PATCH") return handlePatchGroup(request, groupId);
			if (method === "DELETE") return handleDeleteGroup(request, groupId);
		}

		return null;
	}

	return { handleRequest };
}
