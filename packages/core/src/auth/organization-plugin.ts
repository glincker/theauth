import type { TheAuthPlugin } from "../plugin/types.js";
import type { OrgConfig } from "./organization.js";
import { createOrgModule } from "./organization.js";

export type { OrgConfig };

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function jsonResponse(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "Content-Type": "application/json" },
	});
}

async function parseBody(request: Request): Promise<Record<string, unknown>> {
	try {
		return (await request.json()) as Record<string, unknown>;
	} catch {
		return {};
	}
}

// Admin roles that can perform privileged member management actions.
const ADMIN_ROLES = new Set(["owner", "admin"]);

// ---------------------------------------------------------------------------
// Plugin factory
// ---------------------------------------------------------------------------

export function organization(config?: OrgConfig): TheAuthPlugin {
	return {
		id: "theauth-organization",

		async init(ctx): Promise<undefined> {
			const module = createOrgModule(config ?? {}, ctx.db);

			// POST /auth/org/create
			// Creates a new organization. The authenticated user becomes owner.
			ctx.addEndpoint({
				method: "POST",
				path: "/auth/org/create",
				metadata: {
					requireAuth: true,
					description: "Create a new organization owned by the authenticated user",
				},
				async handler(request, endpointCtx) {
					const user = await endpointCtx.getUser(request);
					if (!user) {
						return jsonResponse({ error: "Authentication required" }, 401);
					}

					const body = await parseBody(request);
					const name = typeof body.name === "string" ? body.name.trim() : null;
					const slug = typeof body.slug === "string" ? body.slug.trim() : null;

					if (!name || !slug) {
						return jsonResponse({ error: "Missing required fields: name, slug" }, 400);
					}

					const metadata =
						body.metadata !== undefined &&
						typeof body.metadata === "object" &&
						body.metadata !== null
							? (body.metadata as Record<string, unknown>)
							: undefined;

					try {
						const org = await module.create({ name, slug, ownerId: user.id, metadata });
						return jsonResponse(org, 201);
					} catch (err) {
						return jsonResponse(
							{ error: err instanceof Error ? err.message : "Failed to create organization" },
							400,
						);
					}
				},
			});

			// GET /auth/org/list
			// Returns all organizations the authenticated user is a member of.
			ctx.addEndpoint({
				method: "GET",
				path: "/auth/org/list",
				metadata: {
					requireAuth: true,
					description: "List organizations the authenticated user belongs to",
				},
				async handler(request, endpointCtx) {
					const user = await endpointCtx.getUser(request);
					if (!user) {
						return jsonResponse({ error: "Authentication required" }, 401);
					}

					const orgs = await module.list(user.id);
					return jsonResponse({ organizations: orgs });
				},
			});

			// POST /auth/org/:id/invite
			// Invites a user by email to an organization. Requires admin or owner role.
			ctx.addEndpoint({
				method: "POST",
				path: "/auth/org/:id/invite",
				metadata: {
					requireAuth: true,
					description: "Invite a user to the organization (admin or owner only)",
				},
				async handler(request, endpointCtx) {
					const user = await endpointCtx.getUser(request);
					if (!user) {
						return jsonResponse({ error: "Authentication required" }, 401);
					}

					const url = new URL(request.url);
					const segments = url.pathname.split("/").filter(Boolean);
					// Expected: ["auth", "org", "<id>", "invite"]
					const orgId = segments[2];

					if (!orgId) {
						return jsonResponse({ error: "Missing organization ID in path" }, 400);
					}

					// Verify caller has admin or owner role in this org.
					const member = await module.getMember(orgId, user.id);
					if (!member || !ADMIN_ROLES.has(member.role)) {
						return jsonResponse({ error: "Admin or owner role required" }, 403);
					}

					const body = await parseBody(request);
					const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : null;
					const role = typeof body.role === "string" ? body.role : "member";

					if (!email) {
						return jsonResponse({ error: "Missing required field: email" }, 400);
					}

					try {
						const invitation = await module.invite({
							orgId,
							email,
							role,
							invitedBy: user.id,
						});
						return jsonResponse(invitation, 201);
					} catch (err) {
						return jsonResponse(
							{ error: err instanceof Error ? err.message : "Failed to send invitation" },
							400,
						);
					}
				},
			});

			// POST /auth/org/:id/members
			// Lists all members of the organization.
			ctx.addEndpoint({
				method: "POST",
				path: "/auth/org/:id/members",
				metadata: {
					requireAuth: true,
					description: "List members of the organization",
				},
				async handler(request, endpointCtx) {
					const user = await endpointCtx.getUser(request);
					if (!user) {
						return jsonResponse({ error: "Authentication required" }, 401);
					}

					const url = new URL(request.url);
					const segments = url.pathname.split("/").filter(Boolean);
					// Expected: ["auth", "org", "<id>", "members"]
					const orgId = segments[2];

					if (!orgId) {
						return jsonResponse({ error: "Missing organization ID in path" }, 400);
					}

					// Verify caller is a member of the org before exposing the member list.
					const callerMember = await module.getMember(orgId, user.id);
					if (!callerMember) {
						return jsonResponse({ error: "You are not a member of this organization" }, 403);
					}

					const members = await module.getMembers(orgId);
					return jsonResponse({ members });
				},
			});

			// PATCH /auth/org/:id/members/:userId
			// Updates a member's role. Requires admin or owner.
			ctx.addEndpoint({
				method: "PATCH",
				path: "/auth/org/:id/members/:userId",
				metadata: {
					requireAuth: true,
					description: "Update a member's role (admin or owner only)",
				},
				async handler(request, endpointCtx) {
					const user = await endpointCtx.getUser(request);
					if (!user) {
						return jsonResponse({ error: "Authentication required" }, 401);
					}

					const url = new URL(request.url);
					const segments = url.pathname.split("/").filter(Boolean);
					// Expected: ["auth", "org", "<id>", "members", "<userId>"]
					const orgId = segments[2];
					const targetUserId = segments[4];

					if (!orgId || !targetUserId) {
						return jsonResponse({ error: "Missing organization ID or user ID in path" }, 400);
					}

					const callerMember = await module.getMember(orgId, user.id);
					if (!callerMember || !ADMIN_ROLES.has(callerMember.role)) {
						return jsonResponse({ error: "Admin or owner role required" }, 403);
					}

					const body = await parseBody(request);
					const role = typeof body.role === "string" ? body.role : null;

					if (!role) {
						return jsonResponse({ error: "Missing required field: role" }, 400);
					}

					try {
						const member = await module.updateMemberRole(orgId, targetUserId, role);
						return jsonResponse(member);
					} catch (err) {
						return jsonResponse(
							{ error: err instanceof Error ? err.message : "Failed to update member role" },
							400,
						);
					}
				},
			});

			// DELETE /auth/org/:id/members/:userId
			// Removes a member from the organization. Requires admin or owner.
			ctx.addEndpoint({
				method: "DELETE",
				path: "/auth/org/:id/members/:userId",
				metadata: {
					requireAuth: true,
					description: "Remove a member from the organization (admin or owner only)",
				},
				async handler(request, endpointCtx) {
					const user = await endpointCtx.getUser(request);
					if (!user) {
						return jsonResponse({ error: "Authentication required" }, 401);
					}

					const url = new URL(request.url);
					const segments = url.pathname.split("/").filter(Boolean);
					// Expected: ["auth", "org", "<id>", "members", "<userId>"]
					const orgId = segments[2];
					const targetUserId = segments[4];

					if (!orgId || !targetUserId) {
						return jsonResponse({ error: "Missing organization ID or user ID in path" }, 400);
					}

					const callerMember = await module.getMember(orgId, user.id);
					if (!callerMember || !ADMIN_ROLES.has(callerMember.role)) {
						return jsonResponse({ error: "Admin or owner role required" }, 403);
					}

					try {
						await module.removeMember(orgId, targetUserId);
						return jsonResponse({ removed: true });
					} catch (err) {
						return jsonResponse(
							{ error: err instanceof Error ? err.message : "Failed to remove member" },
							400,
						);
					}
				},
			});
		},
	};
}
