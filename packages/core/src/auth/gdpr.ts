/**
 * GDPR support: data export (Article 20), erasure (Article 17) and anonymization.
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

import { eq, inArray, or } from "drizzle-orm";
import type { SQLiteColumn, SQLiteTable } from "drizzle-orm/sqlite-core";
import { getAuditChainConfig } from "../audit/chain.js";
import { ensureTombstoneAgent, ensureTombstoneUser, eraseAuditIdentity } from "../audit/erasure.js";
import { resolvePseudonymKey } from "../audit/pseudonym.js";
import { hmacSha256 } from "../crypto/web-crypto.js";
import type { Database } from "../db/database.js";
import {
	agentRegistrationTokens,
	agents,
	apiKeys,
	approvalRequests,
	auditLogs,
	budgetPolicies,
	delegationChains,
	emailOtps,
	ephemeralSessions,
	magicLinks,
	oauthAccessTokens,
	oauthAuthorizationCodes,
	organizations,
	orgInvitations,
	orgMembers,
	passkeyCredentials,
	sessions,
	totpRecords,
	users,
} from "../db/schema.js";
import { createDelegationModule } from "../delegation/delegation.js";
import type { RevocationBus } from "../mcp/revocation-bus.js";
import { publishUserRevocation, revokeOwnedAgents } from "./user-revocation.js";

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
	/** Keep anonymized audit logs (default: true). Most compliance frameworks require these records. */
	keepAuditLogs?: boolean;
	/** Also delete organizations owned by this user (default: false). */
	deleteOrganizations?: boolean;
	/** Reason recorded on the MCP revocation rows (default: `gdpr.deleteUser`). */
	revocationReason?: string;
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

	/** Anonymizes user data instead of deleting it. PII is replaced with deterministic anonymous values. */
	anonymizeUser(userId: string): Promise<void>;
}

/**
 * Keyed, stable token for an id, so anonymized audit logs from the same account stay correlated while a list of candidate ids cannot be hashed offline to find the account. HMAC-SHA256 under the per-instance secret (`hmacKey`, else the stored random audit secret), 128 bits, domain separated from the audit pseudonyms. This is pseudonymization: whoever holds the secret can still link ids.
 */
async function keyedToken(key: string, id: string): Promise<string> {
	return (await hmacSha256(key, `theauth.gdpr.anon.v1:${id}`)).slice(0, 32);
}

async function anonymizedUserId(key: string, userId: string): Promise<string> {
	return `[deleted-${await keyedToken(key, userId)}]`;
}

async function anonymizedEmail(key: string, userId: string): Promise<string> {
	return `deleted-${await keyedToken(key, userId)}@anon.invalid`;
}

export function createGdprModule(
	db: Database,
	revocations?: RevocationBus | null,
	options?: { hmacKey?: string },
): GdprModule {
	const delegation = createDelegationModule({ db, ...(revocations ? { revocations } : {}) });
	const anonKey = async (): Promise<string> => {
		const key = await resolvePseudonymKey(
			db,
			options?.hmacKey ?? getAuditChainConfig(db)?.hmacKey,
			true,
		);
		if (!key) throw new Error("could not resolve the anonymization key");
		return key;
	};

	async function exportUserData(userId: string): Promise<UserDataExport> {
		const userRows = await db.select().from(users).where(eq(users.id, userId));
		const user = userRows[0];
		if (!user) {
			throw new Error(`User "${userId}" not found`);
		}

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

		const sessionRows = await db
			.select({ id: sessions.id, createdAt: sessions.createdAt, expiresAt: sessions.expiresAt })
			.from(sessions)
			.where(eq(sessions.userId, userId));

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

	/** Runs `move` (repoint to the tombstone user) only when a row in `table` is owned by `userId`, creating the tombstone on demand. */
	async function moveToTombstone(
		table: SQLiteTable,
		column: SQLiteColumn,
		userId: string,
		anonUserId: string,
		move: () => Promise<unknown>,
	): Promise<void> {
		const found = await db.select({ v: column }).from(table).where(eq(column, userId)).limit(1);
		if (found.length === 0) return;
		await ensureTombstoneUser(db, anonUserId);
		await move();
	}

	async function deleteUser(userId: string, options?: DeleteOptions): Promise<DeleteResult> {
		const keepAuditLogs = options?.keepAuditLogs ?? true;
		const deleteOrgs = options?.deleteOrganizations ?? false;

		const key = await anonKey();
		const ownedAgents = await revokeOwnedAgents(db, userId);
		const agentIds = ownedAgents.map((a) => a.id);
		// Push `sub` and `agent` rows so MCP tokens of the erased user die on every instance.
		await publishUserRevocation(
			revocations,
			userId,
			ownedAgents,
			options?.revocationReason ?? "gdpr.deleteUser",
		);

		// Revoke (never delete) every delegation link the user's agents give or receive, cascading to
		// links further down, so downstream grants cannot outlive the authority they came from.
		let deletedDelegations = 0;
		const linkIds = new Set<string>();
		for (const agentId of agentIds) {
			const links = await db
				.select({ id: delegationChains.id })
				.from(delegationChains)
				.where(
					or(eq(delegationChains.fromAgentId, agentId), eq(delegationChains.toAgentId, agentId)),
				);
			for (const l of links) linkIds.add(l.id);
			for (const id of await delegation.revokeAllForAgent(agentId)) linkIds.add(id);
		}
		deletedDelegations = linkIds.size;

		const sessionRows = await db
			.select({ id: sessions.id })
			.from(sessions)
			.where(eq(sessions.userId, userId));

		const deletedSessions = sessionRows.length;
		await db.delete(sessions).where(eq(sessions.userId, userId));

		const apiKeyRows = await db
			.select({ id: apiKeys.id })
			.from(apiKeys)
			.where(eq(apiKeys.userId, userId));

		const deletedApiKeys = apiKeyRows.length;
		await db.delete(apiKeys).where(eq(apiKeys.userId, userId));

		let anonymizedAuditLogs = 0;
		const anonymizedIds = new Map<string, string>();
		for (const agentId of agentIds)
			anonymizedIds.set(agentId, await anonymizedUserId(key, agentId));

		const anonUserId = await anonymizedUserId(key, userId);
		// The agents are deleted below when audit logs go too. The revoked links stay as a record, so
		// they move to tombstone agents first and the foreign keys hold.
		if (!keepAuditLogs && linkIds.size > 0) {
			await ensureTombstoneUser(db, anonUserId);
			for (const agentId of agentIds) {
				const anonAgentId = anonymizedIds.get(agentId) ?? agentId;
				await ensureTombstoneAgent(db, anonAgentId, anonUserId);
				await db
					.update(delegationChains)
					.set({ fromAgentId: anonAgentId })
					.where(eq(delegationChains.fromAgentId, agentId));
				await db
					.update(delegationChains)
					.set({ toAgentId: anonAgentId })
					.where(eq(delegationChains.toAgentId, agentId));
			}
		}
		// Keeping logs: userId and agentId become stable anonymous tokens that point at tombstone rows.
		anonymizedAuditLogs = await eraseAuditIdentity(db, {
			userId,
			agentIds,
			anonUserId,
			anonAgentId: (agentId) => anonymizedIds.get(agentId) ?? agentId,
			keepRows: keepAuditLogs,
		});
		if (!keepAuditLogs) {
			// Delete mode removes the user's own rows only. Other people's rows that name the user keep no id.
			await db.update(auditLogs).set({ subjectId: null }).where(eq(auditLogs.subjectId, userId));
			await db.update(auditLogs).set({ approverId: null }).where(eq(auditLogs.approverId, userId));
			await db.update(auditLogs).set({ actorId: null }).where(eq(auditLogs.actorId, userId));
			if (agentIds.length > 0) {
				await db
					.update(auditLogs)
					.set({ actorId: null })
					.where(inArray(auditLogs.actorId, agentIds));
			}
		}

		// The user row still exists here, so the FK to users.id is satisfied.
		await db.delete(approvalRequests).where(eq(approvalRequests.userId, userId));

		await db.delete(budgetPolicies).where(eq(budgetPolicies.userId, userId));

		await db.delete(oauthAccessTokens).where(eq(oauthAccessTokens.userId, userId));
		await db.delete(oauthAuthorizationCodes).where(eq(oauthAuthorizationCodes.userId, userId));

		const userRows = await db
			.select({ email: users.email })
			.from(users)
			.where(eq(users.id, userId));

		const userEmail = userRows[0]?.email;
		if (userEmail) {
			await db.delete(magicLinks).where(eq(magicLinks.email, userEmail));
			await db.delete(emailOtps).where(eq(emailOtps.email, userEmail));
		}

		// FK to users.id has no cascade, so delete explicitly.
		await db.delete(totpRecords).where(eq(totpRecords.userId, userId));

		// FK to users.id has no cascade, so delete explicitly.
		await db.delete(passkeyCredentials).where(eq(passkeyCredentials.userId, userId));

		await db.delete(orgMembers).where(eq(orgMembers.userId, userId));

		if (deleteOrgs) {
			// Cascade removes members, invitations and roles.
			await db.delete(organizations).where(eq(organizations.ownerId, userId));
		}

		// keepAuditLogs=true keeps revoked agent rows so audit log references stay valid.
		if (!keepAuditLogs && agentIds.length > 0) {
			await db.delete(agents).where(eq(agents.ownerId, userId));
		} else if (agentIds.length > 0) {
			await moveToTombstone(agents, agents.ownerId, userId, anonUserId, () =>
				db.update(agents).set({ ownerId: anonUserId }).where(eq(agents.ownerId, userId)),
			);
		}
		// Rows that legitimately outlive the user (orgs kept by default, invitations, agent
		// registration tokens and ephemeral sessions) move to the tombstone user, so the FK to
		// users.id holds on every dialect once the real row is gone.
		await moveToTombstone(organizations, organizations.ownerId, userId, anonUserId, () =>
			db
				.update(organizations)
				.set({ ownerId: anonUserId })
				.where(eq(organizations.ownerId, userId)),
		);
		await moveToTombstone(orgInvitations, orgInvitations.invitedBy, userId, anonUserId, () =>
			db
				.update(orgInvitations)
				.set({ invitedBy: anonUserId })
				.where(eq(orgInvitations.invitedBy, userId)),
		);
		await moveToTombstone(
			agentRegistrationTokens,
			agentRegistrationTokens.ownerId,
			userId,
			anonUserId,
			() =>
				db
					.update(agentRegistrationTokens)
					.set({ ownerId: anonUserId })
					.where(eq(agentRegistrationTokens.ownerId, userId)),
		);
		await moveToTombstone(ephemeralSessions, ephemeralSessions.ownerId, userId, anonUserId, () =>
			db
				.update(ephemeralSessions)
				.set({ ownerId: anonUserId })
				.where(eq(ephemeralSessions.ownerId, userId)),
		);
		await db.delete(users).where(eq(users.id, userId));

		return {
			deletedAgents: agentIds.length,
			deletedSessions,
			deletedDelegations,
			deletedApiKeys,
			anonymizedAuditLogs,
		};
	}

	async function anonymizeUser(userId: string): Promise<void> {
		const anonEmail = await anonymizedEmail(await anonKey(), userId);

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

		// Remove passwordless credentials bound to the original email (looked up first).
		await db.delete(totpRecords).where(eq(totpRecords.userId, userId));
		await db.delete(passkeyCredentials).where(eq(passkeyCredentials.userId, userId));
	}

	return { exportUserData, deleteUser, anonymizeUser };
}
