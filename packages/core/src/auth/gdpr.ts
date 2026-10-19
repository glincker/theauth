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
import { getAuditChainConfig } from "../audit/chain.js";
import { resolvePseudonymKey } from "../audit/pseudonym.js";
import type { Database } from "../db/database.js";
import {
	agents,
	apiKeys,
	auditLogs,
	delegationChains,
	organizations,
	orgMembers,
	sessions,
	users,
} from "../db/schema.js";
import { applyWriteOps } from "../db/store/apply-ops.js";
import { createDelegationModule } from "../delegation/delegation.js";
import type { RevocationBus } from "../mcp/revocation-bus.js";
import { anonymizedEmail } from "./gdpr-anon.js";
import { runDeleteUser } from "./gdpr-delete.js";

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

		// Rows about the user, whether or not they own agents.
		const auditRows = await db
			.select({
				action: auditLogs.action,
				resource: auditLogs.resource,
				result: auditLogs.result,
				timestamp: auditLogs.timestamp,
			})
			.from(auditLogs)
			.where(eq(auditLogs.userId, userId));

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

	function deleteUser(userId: string, options?: DeleteOptions): Promise<DeleteResult> {
		return runDeleteUser({ db, revocations, delegation, anonKey }, userId, options);
	}

	async function anonymizeUser(userId: string): Promise<void> {
		const anonEmail = await anonymizedEmail(await anonKey(), userId);
		// Credentials first and the user row last in the same group: the anonymous address is the
		// "done" flag, so a half run (no atomic batch) is finished by calling again.
		await applyWriteOps(db, [
			{ op: "delete", model: "totpRecords", where: [{ field: "userId", op: "eq", value: userId }] },
			{
				op: "delete",
				model: "passkeyCredentials",
				where: [{ field: "userId", op: "eq", value: userId }],
			},
			{
				op: "update",
				model: "users",
				where: [{ field: "id", op: "eq", value: userId }],
				set: {
					email: anonEmail,
					name: null,
					externalId: null,
					metadata: {},
					updatedAt: new Date(),
				},
			},
		]);
	}

	return { exportUserData, deleteUser, anonymizeUser };
}
