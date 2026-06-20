/**
 * Anonymous authentication for TheAuth.
 *
 * Lets users start as guests without providing credentials. The anonymous
 * user can later be upgraded to a real account by supplying an email.
 *
 * Anonymous users are stored in `kavach_users` with a synthetic placeholder
 * email (`anon_<uuid>@theauth.anonymous`) and a metadata flag
 * `{ anonymous: true }`. This satisfies the NOT NULL UNIQUE constraint on
 * the email column while keeping them easily identifiable.
 *
 * @example
 * ```typescript
 * const anon = createAnonymousAuthModule(config, db, sessionManager);
 *
 * // On first visit
 * const { userId, sessionToken } = await anon.createAnonymousUser();
 *
 * // Later, when user signs up
 * await anon.upgradeUser(userId, { email: 'alice@example.com', name: 'Alice' });
 * ```
 */

import { and, eq, lt } from "drizzle-orm";
import { generateId } from "../crypto/web-crypto.js";
import type { Database } from "../db/database.js";
import { sessions, users } from "../db/schema.js";
import type { SessionManager } from "../session/session.js";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface AnonymousAuthConfig {
	/** How long anonymous sessions last in seconds (default: 86400 = 24 hours) */
	sessionTtlSeconds?: number;
	/** Whether to allow anonymous users to create agents (default: false) */
	allowAgentCreation?: boolean;
}

export interface AnonymousAuthModule {
	/** Create an anonymous user and a session. */
	createAnonymousUser(): Promise<{ userId: string; sessionToken: string }>;
	/** Upgrade an anonymous user to a real account by setting their email. */
	upgradeUser(anonymousUserId: string, upgrade: { email: string; name?: string }): Promise<void>;
	/** Check if a user was created as anonymous and has not been upgraded. */
	isAnonymous(userId: string): Promise<boolean>;
	/**
	 * Delete anonymous users older than `maxAgeMs` and their sessions.
	 * Returns the number of users removed.
	 */
	cleanup(maxAgeMs?: number): Promise<number>;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DEFAULT_SESSION_TTL_SECONDS = 60 * 60 * 24; // 24 hours
const DEFAULT_MAX_AGE_MS = 1000 * 60 * 60 * 24; // 24 hours
const ANONYMOUS_EMAIL_DOMAIN = "theauth.anonymous";

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

export function createAnonymousAuthModule(
	config: AnonymousAuthConfig,
	db: Database,
	sessionManager: SessionManager,
): AnonymousAuthModule {
	const sessionTtlSeconds = config.sessionTtlSeconds ?? DEFAULT_SESSION_TTL_SECONDS;

	async function createAnonymousUser(): Promise<{ userId: string; sessionToken: string }> {
		const userId = generateId();
		const now = new Date();

		await db.insert(users).values({
			id: userId,
			email: `anon_${userId}@${ANONYMOUS_EMAIL_DOMAIN}`,
			name: null,
			metadata: { anonymous: true },
			createdAt: now,
			updatedAt: now,
		});

		const { token } = await sessionManager.create(userId, {
			anonymous: true,
			ttl: sessionTtlSeconds,
		});

		return { userId, sessionToken: token };
	}

	async function upgradeUser(
		anonymousUserId: string,
		upgrade: { email: string; name?: string },
	): Promise<void> {
		const rows = await db
			.select({ id: users.id, metadata: users.metadata })
			.from(users)
			.where(eq(users.id, anonymousUserId));

		const row = rows[0];
		if (!row) {
			throw new Error(`User not found: ${anonymousUserId}`);
		}

		const isAnon =
			row.metadata !== null &&
			typeof row.metadata === "object" &&
			(row.metadata as Record<string, unknown>).anonymous === true;

		if (!isAnon) {
			throw new Error(`User ${anonymousUserId} is not an anonymous user`);
		}

		// Rebuild metadata without the anonymous flag (no delete operator).
		const { anonymous: _anon, ...rest } = row.metadata as Record<string, unknown>;
		void _anon;
		const updatedMetadata: Record<string, unknown> = rest;

		await db
			.update(users)
			.set({
				email: upgrade.email,
				name: upgrade.name ?? null,
				metadata: Object.keys(updatedMetadata).length > 0 ? updatedMetadata : null,
				updatedAt: new Date(),
			})
			.where(eq(users.id, anonymousUserId));
	}

	async function isAnonymous(userId: string): Promise<boolean> {
		const rows = await db
			.select({ metadata: users.metadata })
			.from(users)
			.where(eq(users.id, userId));

		const row = rows[0];
		if (!row) return false;

		return (
			row.metadata !== null &&
			typeof row.metadata === "object" &&
			(row.metadata as Record<string, unknown>).anonymous === true
		);
	}

	async function cleanup(maxAgeMs?: number): Promise<number> {
		const cutoff = new Date(Date.now() - (maxAgeMs ?? DEFAULT_MAX_AGE_MS));

		// Find anonymous users older than cutoff.
		const allUsers = await db
			.select({
				id: users.id,
				email: users.email,
				metadata: users.metadata,
				createdAt: users.createdAt,
			})
			.from(users)
			.where(lt(users.createdAt, cutoff));

		const anonymousUserIds = allUsers
			.filter(
				(u) =>
					u.email.endsWith(`@${ANONYMOUS_EMAIL_DOMAIN}`) &&
					u.metadata !== null &&
					typeof u.metadata === "object" &&
					(u.metadata as Record<string, unknown>).anonymous === true,
			)
			.map((u) => u.id);

		if (anonymousUserIds.length === 0) return 0;

		// Delete sessions first (FK constraint).
		for (const userId of anonymousUserIds) {
			await db.delete(sessions).where(eq(sessions.userId, userId));
			await db.delete(users).where(and(eq(users.id, userId)));
		}

		return anonymousUserIds.length;
	}

	return { createAnonymousUser, upgradeUser, isAnonymous, cleanup };
}
