/**
 * Admin module for TheAuth.
 *
 * Global admin operations: user listing, banning, impersonation, and deletion.
 * Admin access is determined by the `adminUserIds` config list.
 *
 * @example
 * ```typescript
 * const kavach = await createKavach({
 *   database: { provider: 'sqlite', url: 'kavach.db' },
 *   admin: { adminUserIds: ['user_abc123'], allowImpersonation: true },
 * });
 *
 * await kavach.admin.banUser('user_xyz', 'Violating terms');
 * const { session } = await kavach.admin.impersonate('user_abc123', 'user_xyz');
 * ```
 */

import { eq, like, sql } from "drizzle-orm";
import type { Database } from "../db/database.js";
import { agents, sessions, users } from "../db/schema.js";
import type { SessionManager } from "../session/session.js";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface AdminConfig {
	/** User IDs that are global admins */
	adminUserIds?: string[];
	/** Allow impersonation (default: true) */
	allowImpersonation?: boolean;
	/** Impersonation session TTL in seconds (default: 3600 = 1 hour) */
	impersonationTtlSeconds?: number;
	/** Callback for audit logging admin actions */
	onAdminAction?: (entry: AdminAuditEntry) => void | Promise<void>;
}

export interface AdminAuditEntry {
	adminUserId: string;
	action: string;
	targetUserId: string;
	details?: Record<string, unknown>;
	timestamp: Date;
}

export interface AdminUser {
	id: string;
	email: string;
	name: string | null;
	banned: boolean;
	banReason?: string;
	banExpiresAt?: Date;
	agentCount: number;
	createdAt: Date;
}

export interface AdminModule {
	isAdmin: (userId: string) => Promise<boolean>;
	listUsers: (options?: {
		limit?: number;
		offset?: number;
		search?: string;
	}) => Promise<{ users: AdminUser[]; total: number }>;
	getUser: (userId: string) => Promise<AdminUser | null>;
	banUser: (userId: string, reason?: string, expiresAt?: Date) => Promise<void>;
	unbanUser: (userId: string) => Promise<void>;
	deleteUser: (userId: string) => Promise<void>;
	impersonate: (
		adminUserId: string,
		targetUserId: string,
	) => Promise<{ session: { token: string; expiresAt: Date }; impersonating: boolean }>;
	stopImpersonation: (sessionToken: string) => Promise<void>;
	forcePasswordReset: (userId: string) => Promise<void>;
	handleRequest: (request: Request) => Promise<Response | null>;
}

// ---------------------------------------------------------------------------
// Internal row type (matches schema with ban columns)
// ---------------------------------------------------------------------------

type UserRow = typeof users.$inferSelect;

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

const DEFAULT_IMPERSONATION_TTL_SECONDS = 3600; // 1 hour

export function createAdminModule(
	config: AdminConfig,
	db: Database,
	sessionManager: SessionManager | null,
): AdminModule {
	const adminUserIds = new Set(config.adminUserIds ?? []);
	const allowImpersonation = config.allowImpersonation ?? true;
	const impersonationTtlSeconds =
		config.impersonationTtlSeconds ?? DEFAULT_IMPERSONATION_TTL_SECONDS;
	const onAdminAction = config.onAdminAction;

	async function logAdminAction(
		adminUserId: string,
		action: string,
		targetUserId: string,
		details?: Record<string, unknown>,
	): Promise<void> {
		if (onAdminAction) {
			try {
				await onAdminAction({
					adminUserId,
					action,
					targetUserId,
					details,
					timestamp: new Date(),
				});
			} catch {
				// Audit logging should never break the admin action
			}
		}
	}

	async function isAdmin(userId: string): Promise<boolean> {
		return adminUserIds.has(userId);
	}

	async function getAgentCountForUser(userId: string): Promise<number> {
		const rows = await db
			.select({ count: sql<number>`count(*)` })
			.from(agents)
			.where(eq(agents.ownerId, userId));
		return Number(rows[0]?.count ?? 0);
	}

	function rowToAdminUser(row: UserRow, agentCount: number): AdminUser {
		const banned = (row.banned ?? 0) === 1;
		return {
			id: row.id,
			email: row.email,
			name: row.name,
			banned,
			banReason: banned && row.banReason ? row.banReason : undefined,
			banExpiresAt: banned && row.banExpiresAt ? row.banExpiresAt : undefined,
			agentCount,
			createdAt: row.createdAt,
		};
	}

	async function listUsers(options?: {
		limit?: number;
		offset?: number;
		search?: string;
	}): Promise<{ users: AdminUser[]; total: number }> {
		const limit = options?.limit ?? 50;
		const offset = options?.offset ?? 0;
		const search = options?.search;

		let rows: UserRow[];
		let countRows: { count: number }[];

		if (search) {
			const pattern = `%${search}%`;
			rows = await db
				.select()
				.from(users)
				.where(like(users.email, pattern))
				.limit(limit)
				.offset(offset);
			countRows = await db
				.select({ count: sql<number>`count(*)` })
				.from(users)
				.where(like(users.email, pattern));
		} else {
			rows = await db.select().from(users).limit(limit).offset(offset);
			countRows = await db.select({ count: sql<number>`count(*)` }).from(users);
		}

		const total = Number(countRows[0]?.count ?? 0);

		const adminUsers = await Promise.all(
			rows.map(async (row) => {
				const agentCount = await getAgentCountForUser(row.id);
				return rowToAdminUser(row, agentCount);
			}),
		);

		return { users: adminUsers, total };
	}

	async function getUser(userId: string): Promise<AdminUser | null> {
		const rows = await db.select().from(users).where(eq(users.id, userId));
		const row = rows[0];
		if (!row) return null;
		const agentCount = await getAgentCountForUser(userId);
		return rowToAdminUser(row, agentCount);
	}

	async function banUser(userId: string, reason?: string, expiresAt?: Date): Promise<void> {
		await db
			.update(users)
			.set({
				banned: 1,
				banReason: reason ?? null,
				banExpiresAt: expiresAt ?? null,
				updatedAt: new Date(),
			})
			.where(eq(users.id, userId));

		// Revoke all active sessions for the banned user
		await db.delete(sessions).where(eq(sessions.userId, userId));

		// Revoke all active agent tokens for the banned user
		await db.update(agents).set({ status: "revoked" }).where(eq(agents.ownerId, userId));

		await logAdminAction("system", "ban_user", userId, {
			reason,
			expiresAt: expiresAt?.toISOString(),
		});
	}

	async function unbanUser(userId: string): Promise<void> {
		await db
			.update(users)
			.set({
				banned: 0,
				banReason: null,
				banExpiresAt: null,
				updatedAt: new Date(),
			})
			.where(eq(users.id, userId));

		await logAdminAction("system", "unban_user", userId);
	}

	async function deleteUser(userId: string): Promise<void> {
		// Revoke sessions first
		await db.delete(sessions).where(eq(sessions.userId, userId));
		// Mark agents as revoked to preserve audit trail
		await db.update(agents).set({ status: "revoked" }).where(eq(agents.ownerId, userId));
		await db.delete(users).where(eq(users.id, userId));

		await logAdminAction("system", "delete_user", userId);
	}

	async function impersonate(
		adminUserId: string,
		targetUserId: string,
	): Promise<{ session: { token: string; expiresAt: Date }; impersonating: boolean }> {
		if (!allowImpersonation) throw new Error("Impersonation is disabled");
		if (!sessionManager) throw new Error("Session manager is required for impersonation");

		const isAdminUser = await isAdmin(adminUserId);
		if (!isAdminUser) throw new Error(`User "${adminUserId}" is not an admin`);

		// Impersonation sessions use a shorter TTL (default: 1 hour)
		const impersonationExpiresAt = new Date(Date.now() + impersonationTtlSeconds * 1000);

		const { token } = await sessionManager.create(targetUserId, {
			impersonating: true,
			adminUserId,
			impersonationExpiresAt: impersonationExpiresAt.toISOString(),
			sessionType: "impersonation",
		});

		await logAdminAction(adminUserId, "impersonate", targetUserId);

		return {
			session: { token, expiresAt: impersonationExpiresAt },
			impersonating: true,
		};
	}

	async function stopImpersonation(sessionToken: string): Promise<void> {
		if (!sessionManager) throw new Error("Session manager is required");
		const session = await sessionManager.validate(sessionToken);
		if (!session) throw new Error("Invalid or expired session token");
		await sessionManager.revoke(session.id);
	}

	async function forcePasswordReset(userId: string): Promise<void> {
		await db
			.update(users)
			.set({ forcePasswordReset: 1, updatedAt: new Date() })
			.where(eq(users.id, userId));

		await logAdminAction("system", "force_password_reset", userId);
	}

	// ── HTTP handler ──────────────────────────────────────────────────────────

	async function handleRequest(request: Request): Promise<Response | null> {
		const url = new URL(request.url);
		const { pathname } = url;
		const { method } = request;

		const json = (data: unknown, status = 200) =>
			new Response(JSON.stringify(data), {
				status,
				headers: { "Content-Type": "application/json" },
			});

		// GET /auth/admin/users
		if (method === "GET" && pathname === "/auth/admin/users") {
			const limit = url.searchParams.get("limit")
				? Number(url.searchParams.get("limit"))
				: undefined;
			const offset = url.searchParams.get("offset")
				? Number(url.searchParams.get("offset"))
				: undefined;
			const search = url.searchParams.get("search") ?? undefined;
			const result = await listUsers({ limit, offset, search });
			return json(result);
		}

		// GET /auth/admin/users/:id
		const userMatch = /^\/auth\/admin\/users\/([^/]+)$/.exec(pathname);
		if (method === "GET" && userMatch) {
			const userId = decodeURIComponent(userMatch[1] ?? "");
			const user = await getUser(userId);
			if (!user) return json({ error: "User not found" }, 404);
			return json(user);
		}

		// POST /auth/admin/users/:id/ban
		const banMatch = /^\/auth\/admin\/users\/([^/]+)\/ban$/.exec(pathname);
		if (method === "POST" && banMatch) {
			const userId = decodeURIComponent(banMatch[1] ?? "");
			let body: Record<string, unknown> = {};
			try {
				body = (await request.json()) as Record<string, unknown>;
			} catch {
				// body is optional
			}
			const reason = typeof body.reason === "string" ? body.reason : undefined;
			const expiresAt = body.expiresAt ? new Date(body.expiresAt as string) : undefined;
			await banUser(userId, reason, expiresAt);
			return json({ success: true });
		}

		// POST /auth/admin/users/:id/unban
		const unbanMatch = /^\/auth\/admin\/users\/([^/]+)\/unban$/.exec(pathname);
		if (method === "POST" && unbanMatch) {
			const userId = decodeURIComponent(unbanMatch[1] ?? "");
			await unbanUser(userId);
			return json({ success: true });
		}

		// DELETE /auth/admin/users/:id
		const deleteMatch = /^\/auth\/admin\/users\/([^/]+)$/.exec(pathname);
		if (method === "DELETE" && deleteMatch) {
			const userId = decodeURIComponent(deleteMatch[1] ?? "");
			await deleteUser(userId);
			return json({ success: true });
		}

		// POST /auth/admin/impersonate/:userId
		const impersonateMatch = /^\/auth\/admin\/impersonate\/([^/]+)$/.exec(pathname);
		if (method === "POST" && impersonateMatch) {
			const targetUserId = decodeURIComponent(impersonateMatch[1] ?? "");
			let body: Record<string, unknown> = {};
			try {
				body = (await request.json()) as Record<string, unknown>;
			} catch {
				return json({ error: "Invalid JSON body" }, 400);
			}
			const adminUserId = body.adminUserId;
			if (typeof adminUserId !== "string") {
				return json({ error: "Missing required field: adminUserId" }, 400);
			}
			try {
				const result = await impersonate(adminUserId, targetUserId);
				return json(result);
			} catch (err) {
				return json({ error: err instanceof Error ? err.message : "Unknown error" }, 403);
			}
		}

		// POST /auth/admin/stop-impersonation
		if (method === "POST" && pathname === "/auth/admin/stop-impersonation") {
			const auth = request.headers.get("Authorization");
			const token = auth?.startsWith("Bearer ") ? auth.slice(7) : null;
			if (!token) return json({ error: "Missing Authorization header" }, 401);
			try {
				await stopImpersonation(token);
				return json({ success: true });
			} catch (err) {
				return json({ error: err instanceof Error ? err.message : "Unknown error" }, 400);
			}
		}

		return null;
	}

	return {
		isAdmin,
		listUsers,
		getUser,
		banUser,
		unbanUser,
		deleteUser,
		impersonate,
		stopImpersonation,
		forcePasswordReset,
		handleRequest,
	};
}
