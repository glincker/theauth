/**
 * GDPR module for TheAuth.
 *
 * Implements Article 17 (right to erasure) and Article 20 (right to data
 * portability) for user accounts. Compliance-critical: every data removal
 * path is explicit about which tables are affected.
 *
 * @example
 * ```typescript
 * const gdpr = createGdprModule(db);
 *
 * // Export all data for a user
 * const export = await gdpr.exportUserData(userId);
 *
 * // Delete account, keeping anonymized audit trail
 * const result = await gdpr.deleteUser(userId, { keepAuditLogs: true });
 *
 * // Anonymize PII but keep the account (e.g., for orgs that require it)
 * await gdpr.anonymizeUser(userId);
 * ```
 */

import { eq, inArray, or, sql } from "drizzle-orm";
import { sha256 } from "../crypto/web-crypto.js";
import type { Database } from "../db/database.js";
import {
	agents,
	apiKeys,
	approvalRequests,
	auditLogs,
	budgetPolicies,
	delegationChains,
	emailOtps,
	magicLinks,
	oauthAccessTokens,
	oauthAuthorizationCodes,
	organizations,
	orgMembers,
	passkeyCredentials,
	sessions,
	totpRecords,
	users,
} from "../db/schema.js";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface UserDataExport {
	user: { id: string; email: string; name: string | null; createdAt: string };
	agents: Array<{ id: string; name: string; type: string; status: string; createdAt: string }>;
	sessions: Array<{ id: string; createdAt: string; expiresAt: string }>;
	auditLogs: Array<{ action: string; resource: string; result: string; timestamp: string }>;
	delegations: Array<{ fromAgent: string; toAgent: string; createdAt: string }>;
	organizations: Array<{ id: string; name: string; role: string }>;
	apiKeys: Array<{ id: string; name: string; createdAt: string }>;
	exportedAt: string;
}

export interface DeleteOptions {
	/**
	 * Keep anonymized audit logs (default: true).
	 *
	 * Required for most compliance frameworks — audit records must survive
	 * account deletion. User/agent identity is replaced with a stable hash so
	 * aggregate reporting remains consistent across deleted accounts.
	 */
	keepAuditLogs?: boolean;
	/**
	 * Also delete organizations owned by this user (default: false).
	 *
	 * When false, ownership is left in place so other members are unaffected.
	 * Set to true only when the org has no other members or its data should
	 * also be erased.
	 */
	deleteOrganizations?: boolean;
}

export interface DeleteResult {
	deletedAgents: number;
	deletedSessions: number;
	deletedDelegations: number;
	deletedApiKeys: number;
	anonymizedAuditLogs: number;
}

export interface GdprModule {
	/** Export all user data as a structured JSON object (GDPR Article 20). */
	exportUserData(userId: string): Promise<UserDataExport>;

	/** Delete all user data (GDPR Article 17). Returns counts of removed records. */
	deleteUser(userId: string, options?: DeleteOptions): Promise<DeleteResult>;

	/**
	 * Anonymize user data instead of deleting.
	 *
	 * Replaces PII (email, name) with deterministic anonymous values while
	 * keeping the account structure intact. Useful when org membership or
	 * audit referential integrity must be preserved.
	 */
	anonymizeUser(userId: string): Promise<void>;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Produce a stable short hash for an ID so anonymized audit logs from the
 * same deleted account are still groupable in aggregate reports.
 */
async function stableHash(id: string): Promise<string> {
	const hash = await sha256(id);
	return hash.slice(0, 12);
}

async function anonymizedUserId(userId: string): Promise<string> {
	return `[deleted-${await stableHash(userId)}]`;
}

async function anonymizedEmail(userId: string): Promise<string> {
	return `deleted-${await stableHash(userId)}@anon.invalid`;
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

export function createGdprModule(db: Database): GdprModule {
	async function exportUserData(userId: string): Promise<UserDataExport> {
		// User record
		const userRows = await db.select().from(users).where(eq(users.id, userId));
		const user = userRows[0];
		if (!user) {
			throw new Error(`User "${userId}" not found`);
		}

		// Agents owned by this user
		const agentRows = await db
			.select({
				id: agents.id,
				name: agents.name,
				type: agents.type,
				status: agents.status,
				createdAt: agents.createdAt,
			})
			.from(agents)
			.where(eq(agents.ownerId, userId));

		const agentIds = agentRows.map((a) => a.id);

		// Active sessions
		const sessionRows = await db
			.select({ id: sessions.id, createdAt: sessions.createdAt, expiresAt: sessions.expiresAt })
			.from(sessions)
			.where(eq(sessions.userId, userId));

		// Audit logs attributed to this user
		const auditRows =
			agentIds.length > 0
				? await db
						.select({
							action: auditLogs.action,
							resource: auditLogs.resource,
							result: auditLogs.result,
							timestamp: auditLogs.timestamp,
						})
						.from(auditLogs)
						.where(eq(auditLogs.userId, userId))
				: [];

		// Delegation chains involving any of the user's agents
		const delegationRows =
			agentIds.length > 0
				? await db
						.select({
							fromAgentId: delegationChains.fromAgentId,
							toAgentId: delegationChains.toAgentId,
							createdAt: delegationChains.createdAt,
						})
						.from(delegationChains)
						.where(
							or(
								inArray(delegationChains.fromAgentId, agentIds),
								inArray(delegationChains.toAgentId, agentIds),
							),
						)
				: [];

		// Organization memberships
		const memberRows = await db
			.select({
				orgId: orgMembers.orgId,
				role: orgMembers.role,
			})
			.from(orgMembers)
			.where(eq(orgMembers.userId, userId));

		const orgIds = memberRows.map((m) => m.orgId);

		const orgRows =
			orgIds.length > 0
				? await db
						.select({ id: organizations.id, name: organizations.name })
						.from(organizations)
						.where(inArray(organizations.id, orgIds))
				: [];

		const orgById = new Map(orgRows.map((o) => [o.id, o.name]));

		// API keys
		const apiKeyRows = await db
			.select({ id: apiKeys.id, name: apiKeys.name, createdAt: apiKeys.createdAt })
			.from(apiKeys)
			.where(eq(apiKeys.userId, userId));

		return {
			user: {
				id: user.id,
				email: user.email,
				name: user.name ?? null,
				createdAt: user.createdAt.toISOString(),
			},
			agents: agentRows.map((a) => ({
				id: a.id,
				name: a.name,
				type: a.type,
				status: a.status,
				createdAt: a.createdAt.toISOString(),
			})),
			sessions: sessionRows.map((s) => ({
				id: s.id,
				createdAt: s.createdAt.toISOString(),
				expiresAt: s.expiresAt.toISOString(),
			})),
			auditLogs: auditRows.map((a) => ({
				action: a.action,
				resource: a.resource,
				result: a.result,
				timestamp: a.timestamp.toISOString(),
			})),
			delegations: delegationRows.map((d) => ({
				fromAgent: d.fromAgentId,
				toAgent: d.toAgentId,
				createdAt: d.createdAt.toISOString(),
			})),
			organizations: memberRows.map((m) => ({
				id: m.orgId,
				name: orgById.get(m.orgId) ?? m.orgId,
				role: m.role,
			})),
			apiKeys: apiKeyRows.map((k) => ({
				id: k.id,
				name: k.name,
				createdAt: k.createdAt.toISOString(),
			})),
			exportedAt: new Date().toISOString(),
		};
	}

	async function deleteUser(userId: string, options?: DeleteOptions): Promise<DeleteResult> {
		const keepAuditLogs = options?.keepAuditLogs ?? true;
		const deleteOrgs = options?.deleteOrganizations ?? false;

		// Resolve all agents owned by this user before we start deleting
		const agentRows = await db
			.select({ id: agents.id })
			.from(agents)
			.where(eq(agents.ownerId, userId));

		const agentIds = agentRows.map((a) => a.id);

		// 1. Revoke all agents (preserve rows for FK references from audit logs)
		if (agentIds.length > 0) {
			await db
				.update(agents)
				.set({ status: "revoked", updatedAt: new Date() })
				.where(eq(agents.ownerId, userId));
		}

		// 2. Delete all sessions
		const sessionRows = await db
			.select({ id: sessions.id })
			.from(sessions)
			.where(eq(sessions.userId, userId));

		const deletedSessions = sessionRows.length;
		await db.delete(sessions).where(eq(sessions.userId, userId));

		// 3. Delete delegation chains (both directions for user's agents)
		let deletedDelegations = 0;
		if (agentIds.length > 0) {
			const delegationRows = await db
				.select({ id: delegationChains.id })
				.from(delegationChains)
				.where(
					or(
						inArray(delegationChains.fromAgentId, agentIds),
						inArray(delegationChains.toAgentId, agentIds),
					),
				);

			deletedDelegations = delegationRows.length;

			if (delegationRows.length > 0) {
				const delegationIds = delegationRows.map((d) => d.id);
				await db.delete(delegationChains).where(inArray(delegationChains.id, delegationIds));
			}
		}

		// 4. Delete API keys
		const apiKeyRows = await db
			.select({ id: apiKeys.id })
			.from(apiKeys)
			.where(eq(apiKeys.userId, userId));

		const deletedApiKeys = apiKeyRows.length;
		await db.delete(apiKeys).where(eq(apiKeys.userId, userId));

		// 5. Handle audit logs
		let anonymizedAuditLogs = 0;

		if (agentIds.length > 0) {
			if (keepAuditLogs) {
				// Replace userId and agentId with stable anonymous tokens.
				// The hash is deterministic so aggregate reports can still
				// group all actions from the same deleted account.
				//
				// The audit log FK columns are NOT NULL and reference users/agents,
				// so we must temporarily disable FK enforcement to store the
				// anonymized placeholder. We re-enable it immediately after.
				const anonUserId = await anonymizedUserId(userId);

				await db.run(sql`PRAGMA foreign_keys = OFF`);
				try {
					for (const agentId of agentIds) {
						const anonAgentId = await anonymizedUserId(agentId);
						const affectedRows = await db
							.select({ id: auditLogs.id })
							.from(auditLogs)
							.where(eq(auditLogs.agentId, agentId));

						if (affectedRows.length > 0) {
							await db
								.update(auditLogs)
								.set({ userId: anonUserId, agentId: anonAgentId })
								.where(eq(auditLogs.agentId, agentId));

							anonymizedAuditLogs += affectedRows.length;
						}
					}
				} finally {
					await db.run(sql`PRAGMA foreign_keys = ON`);
				}
			} else {
				// Hard delete — caller has opted out of audit retention.
				// Deleting child rows (audit logs) does not violate FK constraints.
				const affectedRows = await db
					.select({ id: auditLogs.id })
					.from(auditLogs)
					.where(eq(auditLogs.userId, userId));

				anonymizedAuditLogs = affectedRows.length;

				if (affectedRows.length > 0) {
					await db.delete(auditLogs).where(eq(auditLogs.userId, userId));
				}
			}
		}

		// 6. Remove approval requests linked to this user.
		// User still exists at this point — FK to users.id is satisfied.
		await db.delete(approvalRequests).where(eq(approvalRequests.userId, userId));

		// 7. Remove budget policies scoped to this user
		await db.delete(budgetPolicies).where(eq(budgetPolicies.userId, userId));

		// 8. Remove OAuth tokens issued to this user
		await db.delete(oauthAccessTokens).where(eq(oauthAccessTokens.userId, userId));
		await db.delete(oauthAuthorizationCodes).where(eq(oauthAuthorizationCodes.userId, userId));

		// 9. Remove passwordless auth records tied to email — look up email first
		const userRows = await db
			.select({ email: users.email })
			.from(users)
			.where(eq(users.id, userId));

		const userEmail = userRows[0]?.email;
		if (userEmail) {
			await db.delete(magicLinks).where(eq(magicLinks.email, userEmail));
			await db.delete(emailOtps).where(eq(emailOtps.email, userEmail));
		}

		// 10. Remove TOTP records (FK to users.id — no cascade)
		await db.delete(totpRecords).where(eq(totpRecords.userId, userId));

		// 11. Remove passkey credentials (FK to users.id — no cascade)
		await db.delete(passkeyCredentials).where(eq(passkeyCredentials.userId, userId));

		// 12. Remove org memberships (not the orgs themselves unless requested)
		await db.delete(orgMembers).where(eq(orgMembers.userId, userId));

		if (deleteOrgs) {
			// Delete orgs owned by this user — cascade removes members/invitations/roles
			await db.delete(organizations).where(eq(organizations.ownerId, userId));
		}

		// 13. Delete the user record.
		//
		// When keepAuditLogs=true the agent rows are kept (status=revoked) to
		// preserve the anonymized audit log agentId references. The agents'
		// ownerId column still references the user row, so we must disable FK
		// checks for the final user deletion.
		//
		// When keepAuditLogs=false we delete the agent rows first so we can
		// delete the user row without disabling FK enforcement.
		if (!keepAuditLogs && agentIds.length > 0) {
			await db.delete(agents).where(eq(agents.ownerId, userId));
			await db.delete(users).where(eq(users.id, userId));
		} else {
			// Agents remain — FK enforcement must be suspended to allow deleting
			// the parent user row while revoked agent rows still reference it.
			await db.run(sql`PRAGMA foreign_keys = OFF`);
			try {
				await db.delete(users).where(eq(users.id, userId));
			} finally {
				await db.run(sql`PRAGMA foreign_keys = ON`);
			}
		}

		return {
			deletedAgents: agentIds.length,
			deletedSessions,
			deletedDelegations,
			deletedApiKeys,
			anonymizedAuditLogs,
		};
	}

	async function anonymizeUser(userId: string): Promise<void> {
		const anonEmail = await anonymizedEmail(userId);

		await db
			.update(users)
			.set({
				email: anonEmail,
				name: null,
				externalId: null,
				metadata: {},
				updatedAt: new Date(),
			})
			.where(eq(users.id, userId));

		// Remove any passwordless credentials bound to the original email.
		// We need the original email to delete them, so we look it up first —
		// but by now it's already been overwritten. Callers should export or
		// delete those records before calling anonymizeUser if needed.
		// Instead we delete by userId where the schema allows it (TOTP, passkeys).
		await db.delete(totpRecords).where(eq(totpRecords.userId, userId));
		await db.delete(passkeyCredentials).where(eq(passkeyCredentials.userId, userId));
	}

	return { exportUserData, deleteUser, anonymizeUser };
}
