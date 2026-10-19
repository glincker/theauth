import { forbidden, resolveHandlerActor } from "./handler-guard.js";
import { errorResponse, jsonResponse } from "./organization-helpers.js";
import type { OrgConfig, OrgModule, OrgRole } from "./organization-types.js";
import type { ModuleRequestDeps } from "./request-user.js";

/** What the HTTP layer needs beyond the module functions. */
export interface OrgHandlerGuard {
	deps: ModuleRequestDeps;
	config: OrgConfig;
	/** Org and invited email of an invitation: revocation is limited to that org's admins, acceptance to that email. */
	invitationOf: (invitationId: string) => Promise<{ orgId: string; email: string } | null>;
	/** Email of a user, to match an invitation on accept. */
	userEmail: (userId: string) => Promise<string | null>;
}

const OWNER = "owner";
const ADMIN_ROLES = new Set([OWNER, "admin"]);

/**
 * HTTP request routing for the organization module.
 * Fails closed: without an authenticate resolver (and without `trustedServerUse`) every route answers 401.
 * With a resolver, the caller must be a member of the org to read it and an owner or admin to change it, and ids
 * the caller could otherwise forge (owner, inviter, accepting user) are bound to the authenticated user.
 * Owner level stays with owners: only an owner grants the owner role, changes or removes another owner, or
 * deletes the org. An invitation can only be accepted by the user whose email it was sent to.
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

	/** True when the caller may act at owner level: trusted server use, or an owner of the org. */
	async function actsAsOwner(orgId: string, actor: string | null): Promise<boolean> {
		if (actor === null) return true;
		return (await getMember(orgId, actor))?.role === OWNER;
	}

	/** Role the request body asks for, read from a clone so the route can still parse the body. */
	async function requestedRole(request: Request): Promise<string | undefined> {
		try {
			const body = (await request.clone().json()) as { role?: unknown };
			return typeof body.role === "string" ? body.role : undefined;
		} catch {
			return undefined;
		}
	}

	/** Owner-only operations inside an org, checked after membership. Null when allowed. */
	async function denyOwnerLevel(
		request: Request,
		method: string,
		subPath: string,
		orgId: string,
		actor: string | null,
	): Promise<Response | null> {
		if (actor === null) return null;
		const memberMatch = subPath.match(/^\/members\/([^/]+)$/);
		const target = memberMatch?.[1];
		let ownerOnly = false;
		if (method === "DELETE" && subPath === "") ownerOnly = true;
		else if (method === "POST" && (subPath === "/members" || subPath === "/invite")) {
			ownerOnly = (await requestedRole(request)) === OWNER;
		} else if (method === "PATCH" && target) {
			ownerOnly =
				(await requestedRole(request)) === OWNER ||
				(await getMember(orgId, target))?.role === OWNER;
		} else if (method === "DELETE" && target && target !== actor) {
			ownerOnly = (await getMember(orgId, target))?.role === OWNER;
		}
		if (ownerOnly && !(await actsAsOwner(orgId, actor))) return forbidden();
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
		// Pending invitation ids work as bearer links, so listing them needs owner or admin too.
		const isRead = method === "GET" && subPath !== "/invitations";
		const selfRemoval = method === "DELETE" && subPath === `/members/${actor}`;
		const denied =
			(await denyUnlessMember(orgId, actor, !isRead && !selfRemoval)) ??
			(await denyOwnerLevel(request, method, subPath, orgId, actor));
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

	/** The signed-in user is the one the invitation was sent to (emails compared case-insensitively). An unknown invitation passes so accept reports it. */
	async function invitedActor(invitationId: string, actor: string): Promise<boolean> {
		const invitation = await guard.invitationOf(invitationId);
		if (!invitation) return true;
		const email = await guard.userEmail(actor);
		return email !== null && email.trim().toLowerCase() === invitation.email.trim().toLowerCase();
	}

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
				if (actor !== null && !(await invitedActor(invitationId, actor))) return forbidden();
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
				const invitation = await guard.invitationOf(invitationId);
				if (!invitation) return errorResponse("Invitation not found", 404);
				const denied = await denyUnlessMember(invitation.orgId, actor, true);
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
