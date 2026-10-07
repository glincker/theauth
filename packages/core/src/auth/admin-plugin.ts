import { json, parseBody } from "../plugin/helpers.js";
import type { TheAuthPlugin } from "../plugin/types.js";
import type { AdminConfig } from "./admin.js";
import { createAdminModule } from "./admin.js";

export type { AdminConfig };

// ---------------------------------------------------------------------------
// Plugin factory
// ---------------------------------------------------------------------------

export function admin(config?: AdminConfig): TheAuthPlugin {
	return {
		id: "theauth-admin",

		async init(ctx): Promise<undefined> {
			const module = createAdminModule(config ?? {}, ctx.db, ctx.sessionManager ?? null);

			// GET /auth/admin/users
			// Lists all users. Requires admin.
			ctx.addEndpoint({
				method: "GET",
				path: "/auth/admin/users",
				metadata: {
					requireAuth: true,
					description: "List all users (admin only)",
				},
				async handler(request, endpointCtx) {
					const user = await endpointCtx.getUser(request);
					if (!user) {
						return json({ error: "Authentication required" }, 401);
					}

					const isAdminUser = await module.isAdmin(user.id);
					if (!isAdminUser) {
						return json({ error: "Admin access required" }, 403);
					}

					const url = new URL(request.url);
					const limitParam = url.searchParams.get("limit");
					const offsetParam = url.searchParams.get("offset");
					const search = url.searchParams.get("search") ?? undefined;

					const result = await module.listUsers({
						limit: limitParam ? Number(limitParam) : undefined,
						offset: offsetParam ? Number(offsetParam) : undefined,
						search,
					});

					return json(result);
				},
			});

			// GET /auth/admin/users/:id
			// Returns a single user by ID. Requires admin.
			ctx.addEndpoint({
				method: "GET",
				path: "/auth/admin/users/:id",
				metadata: {
					requireAuth: true,
					description: "Get a user by ID (admin only)",
				},
				async handler(request, endpointCtx) {
					const user = await endpointCtx.getUser(request);
					if (!user) {
						return json({ error: "Authentication required" }, 401);
					}

					const isAdminUser = await module.isAdmin(user.id);
					if (!isAdminUser) {
						return json({ error: "Admin access required" }, 403);
					}

					const url = new URL(request.url);
					const segments = url.pathname.split("/").filter(Boolean);
					// Expected: ["auth", "admin", "users", "<id>"]
					const targetId = segments[3];

					if (!targetId) {
						return json({ error: "Missing user ID in path" }, 400);
					}

					const found = await module.getUser(decodeURIComponent(targetId));
					if (!found) {
						return json({ error: "User not found" }, 404);
					}

					return json(found);
				},
			});

			// POST /auth/admin/users/:id/ban
			// Bans a user. Optionally accepts { reason, expiresAt } in body. Requires admin.
			ctx.addEndpoint({
				method: "POST",
				path: "/auth/admin/users/:id/ban",
				metadata: {
					requireAuth: true,
					description: "Ban a user (admin only)",
				},
				async handler(request, endpointCtx) {
					const user = await endpointCtx.getUser(request);
					if (!user) {
						return json({ error: "Authentication required" }, 401);
					}

					const isAdminUser = await module.isAdmin(user.id);
					if (!isAdminUser) {
						return json({ error: "Admin access required" }, 403);
					}

					const url = new URL(request.url);
					const segments = url.pathname.split("/").filter(Boolean);
					// Expected: ["auth", "admin", "users", "<id>", "ban"]
					const targetId = segments[3];

					if (!targetId) {
						return json({ error: "Missing user ID in path" }, 400);
					}

					const bodyResult = await parseBody(request);
					if (!bodyResult.ok) return bodyResult.response;
					const reason =
						typeof bodyResult.data.reason === "string" ? bodyResult.data.reason : undefined;
					const expiresAt = bodyResult.data.expiresAt
						? new Date(bodyResult.data.expiresAt as string)
						: undefined;

					await module.banUser(decodeURIComponent(targetId), reason, expiresAt);
					return json({ success: true });
				},
			});

			// POST /auth/admin/users/:id/unban
			// Lifts a ban from a user. Requires admin.
			ctx.addEndpoint({
				method: "POST",
				path: "/auth/admin/users/:id/unban",
				metadata: {
					requireAuth: true,
					description: "Unban a user (admin only)",
				},
				async handler(request, endpointCtx) {
					const user = await endpointCtx.getUser(request);
					if (!user) {
						return json({ error: "Authentication required" }, 401);
					}

					const isAdminUser = await module.isAdmin(user.id);
					if (!isAdminUser) {
						return json({ error: "Admin access required" }, 403);
					}

					const url = new URL(request.url);
					const segments = url.pathname.split("/").filter(Boolean);
					// Expected: ["auth", "admin", "users", "<id>", "unban"]
					const targetId = segments[3];

					if (!targetId) {
						return json({ error: "Missing user ID in path" }, 400);
					}

					await module.unbanUser(decodeURIComponent(targetId));
					return json({ success: true });
				},
			});

			// DELETE /auth/admin/users/:id
			// Permanently deletes a user. Requires admin.
			ctx.addEndpoint({
				method: "DELETE",
				path: "/auth/admin/users/:id",
				metadata: {
					requireAuth: true,
					description: "Delete a user (admin only)",
				},
				async handler(request, endpointCtx) {
					const user = await endpointCtx.getUser(request);
					if (!user) {
						return json({ error: "Authentication required" }, 401);
					}

					const isAdminUser = await module.isAdmin(user.id);
					if (!isAdminUser) {
						return json({ error: "Admin access required" }, 403);
					}

					const url = new URL(request.url);
					const segments = url.pathname.split("/").filter(Boolean);
					// Expected: ["auth", "admin", "users", "<id>"]
					const targetId = segments[3];

					if (!targetId) {
						return json({ error: "Missing user ID in path" }, 400);
					}

					await module.deleteUser(decodeURIComponent(targetId));
					return json({ success: true });
				},
			});

			// POST /auth/admin/users/:id/impersonate
			// Starts an impersonation session as the target user. Requires admin.
			ctx.addEndpoint({
				method: "POST",
				path: "/auth/admin/users/:id/impersonate",
				metadata: {
					requireAuth: true,
					description: "Start an impersonation session as a target user (admin only)",
				},
				async handler(request, endpointCtx) {
					const user = await endpointCtx.getUser(request);
					if (!user) {
						return json({ error: "Authentication required" }, 401);
					}

					const isAdminUser = await module.isAdmin(user.id);
					if (!isAdminUser) {
						return json({ error: "Admin access required" }, 403);
					}

					const url = new URL(request.url);
					const segments = url.pathname.split("/").filter(Boolean);
					// Expected: ["auth", "admin", "users", "<id>", "impersonate"]
					const targetId = segments[3];

					if (!targetId) {
						return json({ error: "Missing user ID in path" }, 400);
					}

					try {
						const result = await module.impersonate(user.id, decodeURIComponent(targetId));
						return json(result);
					} catch (err) {
						return json(
							{ error: err instanceof Error ? err.message : "Impersonation failed" },
							403,
						);
					}
				},
			});
		},
	};
}
