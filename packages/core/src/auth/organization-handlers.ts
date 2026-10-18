import { errorResponse, jsonResponse } from "./organization-helpers.js";
import type { OrgModule, OrgRole } from "./organization-types.js";

/** HTTP request routing for the organization module. */
export function createOrgHandlers(
	ctx: Omit<OrgModule, "handleRequest">,
): Pick<OrgModule, "handleRequest"> {
	const {
		get,
		addMember,
		create,
		list,
		update,
		remove,
		removeMember,
		updateMemberRole,
		getMembers,
		invite,
		listInvitations,
		hasPermission,
		getRoles,
		createRole,
		acceptInvitation,
		revokeInvitation,
	} = ctx;

	async function handleRequest(request: Request): Promise<Response | null> {
		const url = new URL(request.url);
		const { pathname } = url;
		const method = request.method.toUpperCase();

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

		if (method === "GET" && subPath === "") {
			const org = await get(orgId);
			if (!org) return errorResponse("Organization not found", 404);
			return jsonResponse(org);
		}

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

		if (method === "DELETE" && subPath === "") {
			try {
				await remove(orgId);
				return jsonResponse({ success: true });
			} catch (err) {
				return errorResponse(err instanceof Error ? err.message : "Unknown error", 400);
			}
		}

		if (method === "POST" && subPath === "/members") {
			try {
				const body = (await request.json()) as { userId: string; role: string };
				const member = await addMember(orgId, body.userId, body.role);
				return jsonResponse(member, 201);
			} catch (err) {
				return errorResponse(err instanceof Error ? err.message : "Unknown error", 400);
			}
		}

		if (method === "GET" && subPath === "/members") {
			const members = await getMembers(orgId);
			return jsonResponse(members);
		}

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

		if (method === "DELETE" && memberMatch) {
			const userId = memberMatch[1];
			if (!userId) return errorResponse("Missing userId", 400);
			await removeMember(orgId, userId);
			return jsonResponse({ success: true });
		}

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

		if (method === "GET" && subPath === "/invitations") {
			const invitations = await listInvitations(orgId);
			return jsonResponse(invitations);
		}

		const permMatch = subPath.match(/^\/permissions\/([^/]+)\/([^/]+)$/);
		if (method === "GET" && permMatch) {
			const userId = permMatch[1];
			const permission = permMatch[2];
			if (!userId || !permission) return errorResponse("Missing userId or permission", 400);
			const allowed = await hasPermission(orgId, userId, permission);
			return jsonResponse({ allowed });
		}

		if (method === "POST" && subPath === "/roles") {
			try {
				const body = (await request.json()) as OrgRole;
				const role = await createRole(orgId, body);
				return jsonResponse(role, 201);
			} catch (err) {
				return errorResponse(err instanceof Error ? err.message : "Unknown error", 400);
			}
		}

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
		handleRequest: handleRequestWithInviteRoutes,
	};
}
