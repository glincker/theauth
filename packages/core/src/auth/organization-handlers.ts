import { forbidden, resolveHandlerActor } from "./handler-guard.js";
import { errorResponse, jsonResponse } from "./organization-helpers.js";
import type { OrgConfig, OrgModule, OrgRole } from "./organization-types.js";
import type { ModuleRequestDeps } from "./request-user.js";

/** What the HTTP layer needs beyond the module functions. */
export interface OrgHandlerGuard {
	deps: ModuleRequestDeps;
	config: OrgConfig;
	/** Org that owns an invitation, so invite revocation can be limited to that org's admins. */
	invitationOrgId: (invitationId: string) => Promise<string | null>;
}

const ADMIN_ROLES = new Set(["owner", "admin"]);

/**
 * HTTP request routing for the organization module.
 * Fails closed: without an authenticate resolver (and without `trustedServerUse`) every route answers 401.
 * With a resolver, the caller must be a member of the org to read it and an owner or admin to change it, and ids
 * the caller could otherwise forge (owner, inviter, accepting user) are bound to the authenticated user.
 */
export function createOrgHandlers(
	ctx: Omit<OrgModule, "handleRequest">,
	guard: OrgHandlerGuard,
): Pick<OrgModule, "handleRequest"> {
	const {
		get,
		getMember,
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

	/** Null when allowed. `actor` null means trusted server use. */
	async function denyUnlessMember(
		orgId: string,
		actor: string | null,
		admin: boolean,
	): Promise<Response | null> {
		if (actor === null) return null;
		const member = await getMember(orgId, actor);
		if (!member) return forbidden();
		if (admin && !ADMIN_ROLES.has(member.role)) return forbidden();
		return null;
	}

	async function handleRequest(request: Request, actor: string | null): Promise<Response | null> {
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
				if (actor !== null) {
					if (body.ownerId !== undefined && body.ownerId !== actor) return forbidden();
					body.ownerId = actor;
				}
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
			if (actor !== null && userId !== actor) return forbidden();
			const orgs = await list(userId);
			return jsonResponse(orgs);
		}

		// Routes with orgId: /auth/org/:orgId or /auth/org/:orgId/...
		const orgBaseMatch = pathname.match(/^\/auth\/org\/([^/]+)(\/.*)?$/);
		if (!orgBaseMatch) return null;

		const orgId = orgBaseMatch[1];
		if (!orgId) return null;

		const subPath = orgBaseMatch[2] ?? "";

		// Reads need membership. Changes need owner or admin. A member may remove themselves.
		const isRead = method === "GET";
		const selfRemoval = method === "DELETE" && subPath === `/members/${actor}`;
		const denied = await denyUnlessMember(orgId, actor, !isRead && !selfRemoval);
		if (denied) return denied;

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
				if (actor !== null) body.invitedBy = actor;
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

	async function route(request: Request, actor: string | null): Promise<Response | null> {
		const url = new URL(request.url);
		const { pathname } = url;
		const method = request.method.toUpperCase();

		const acceptMatch = pathname.match(/^\/auth\/org\/invite\/([^/]+)\/accept$/);
		if (method === "POST" && acceptMatch) {
			const invitationId = acceptMatch[1];
			if (!invitationId) return errorResponse("Missing invitationId", 400);
			try {
				const body = (await request.json()) as { userId?: string };
				if (actor !== null && body.userId !== undefined && body.userId !== actor)
					return forbidden();
				const member = await acceptInvitation(invitationId, actor ?? body.userId ?? "");
				return jsonResponse(member, 201);
			} catch (err) {
				return errorResponse(err instanceof Error ? err.message : "Unknown error", 400);
			}
		}

		const revokeMatch = pathname.match(/^\/auth\/org\/invite\/([^/]+)$/);
		if (method === "DELETE" && revokeMatch) {
			const invitationId = revokeMatch[1];
			if (!invitationId) return errorResponse("Missing invitationId", 400);
			if (actor !== null) {
				const owningOrg = await guard.invitationOrgId(invitationId);
				if (!owningOrg) return errorResponse("Invitation not found", 404);
				const denied = await denyUnlessMember(owningOrg, actor, true);
				if (denied) return denied;
			}
			await revokeInvitation(invitationId);
			return jsonResponse({ success: true });
		}

		return handleRequest(request, actor);
	}

	async function guarded(request: Request): Promise<Response | null> {
		const { pathname } = new URL(request.url);
		if (pathname !== "/auth/org" && !pathname.startsWith("/auth/org/")) return null;
		const actor = await resolveHandlerActor(request, guard.deps, guard.config);
		if (actor.kind === "denied") return actor.response;
		return route(request, actor.kind === "user" ? actor.userId : null);
	}

	return {
		handleRequest: guarded,
	};
}
