/**
 * GDPR deleteUser as an ordered list of steps. There is no transaction around the whole thing (D1 has none), so instead every step is safe to rerun and a progress marker (gdpr-progress.ts) records how many steps finished. A crash at any statement is repaired by calling `deleteUser` again: it resumes at the first unfinished step. Write-only runs inside a step go through one atomic batch where the backend has it. Design: docs-local/design/db-adapter-abstraction.md section 2.
 */
import { eq, inArray, or } from "drizzle-orm";
import { ensureTombstoneAgent, ensureTombstoneUser, eraseAuditIdentity } from "../audit/erasure.js";
import type { Database } from "../db/database.js";
import {
	agents,
	apiKeys,
	approvalRequests,
	delegationChains,
	organizations,
	sessions,
	users,
} from "../db/schema.js";
import { applyWriteOps } from "../db/store/apply-ops.js";
import type { Where, WriteOp } from "../db/store/types.js";
import type { createDelegationModule } from "../delegation/delegation.js";
import type { RevocationBus } from "../mcp/revocation-bus.js";
import type { DeleteOptions, DeleteResult } from "./gdpr.js";
import { anonymizedUserId } from "./gdpr-anon.js";
import type { ErasureMarker } from "./gdpr-progress.js";
import { readErasureMarker, saveErasureMarker } from "./gdpr-progress.js";
import { orgRemoveOps } from "./organization-core.js";
import { publishUserRevocation, revokeOwnedAgents } from "./user-revocation.js";

export interface DeleteContext {
	db: Database;
	revocations?: RevocationBus | null;
	delegation: ReturnType<typeof createDelegationModule>;
	anonKey: () => Promise<string>;
}

const eqWhere = (field: string, value: string): Where[] => [{ field, op: "eq", value }];

function resultOf(m: ErasureMarker): DeleteResult {
	return {
		deletedAgents: m.deletedAgents,
		deletedSessions: m.counts.deletedSessions,
		deletedDelegations: m.counts.deletedDelegations,
		deletedApiKeys: m.counts.deletedApiKeys,
		anonymizedAuditLogs: m.counts.anonymizedAuditLogs,
	};
}

export async function runDeleteUser(
	ctx: DeleteContext,
	userId: string,
	options?: DeleteOptions,
): Promise<DeleteResult> {
	const { db } = ctx;
	const key = await ctx.anonKey();
	const anonUserId = await anonymizedUserId(key, userId);

	// Owned agents are read before the marker, so a call that sees no marker has not seen any agent move.
	const userExists =
		(await db.select({ id: users.id }).from(users).where(eq(users.id, userId))).length > 0;
	const ownedIds = (
		await db.select({ id: agents.id }).from(agents).where(eq(agents.ownerId, userId))
	)
		.map((r) => r.id)
		.sort();
	let marker = await readErasureMarker(db, anonUserId);
	if (marker?.done && !userExists) return resultOf(marker);
	if (marker?.done) marker = null; // the id was reused after an earlier erasure

	if (!marker) {
		await ensureTombstoneUser(db, anonUserId);
		const raced = await readErasureMarker(db, anonUserId);
		marker = raced ?? {
			v: 1,
			completed: 0,
			done: false,
			agentIds: ownedIds,
			keepAuditLogs: options?.keepAuditLogs ?? true,
			deleteOrganizations: options?.deleteOrganizations ?? false,
			deletedAgents: ownedIds.length,
			counts: {
				deletedSessions: 0,
				deletedDelegations: 0,
				deletedApiKeys: 0,
				anonymizedAuditLogs: 0,
			},
		};
		if (!raced || raced.done) await saveErasureMarker(db, anonUserId, marker, true);
	}
	if (marker.done) return resultOf(marker);
	// Options and agent list are the ones the finished steps ran under.
	const m: ErasureMarker = marker;
	const agentIds = m.agentIds;
	const keep = m.keepAuditLogs;
	const anonOf = new Map<string, string>();
	for (const id of agentIds) anonOf.set(id, await anonymizedUserId(key, id));
	const anonAgent = (id: string): string => anonOf.get(id) ?? id;

	const steps: Array<() => Promise<void>> = [
		// 0: revoke agents and delegations, push the revocations
		async () => {
			const revoked = await revokeOwnedAgents(db, userId);
			await publishUserRevocation(
				ctx.revocations,
				userId,
				revoked,
				options?.revocationReason ?? "gdpr.deleteUser",
			);
			const linkIds = new Set<string>();
			for (const agentId of agentIds) {
				const links = await db
					.select({ id: delegationChains.id })
					.from(delegationChains)
					.where(
						or(eq(delegationChains.fromAgentId, agentId), eq(delegationChains.toAgentId, agentId)),
					);
				for (const l of links) linkIds.add(l.id);
				for (const id of await ctx.delegation.revokeAllForAgent(agentId)) linkIds.add(id);
			}
			m.counts.deletedDelegations = Math.max(m.counts.deletedDelegations, linkIds.size);
		},
		// 1: sessions and API keys
		async () => {
			const s = await db
				.select({ id: sessions.id })
				.from(sessions)
				.where(eq(sessions.userId, userId));
			const k = await db.select({ id: apiKeys.id }).from(apiKeys).where(eq(apiKeys.userId, userId));
			m.counts.deletedSessions = Math.max(m.counts.deletedSessions, s.length);
			m.counts.deletedApiKeys = Math.max(m.counts.deletedApiKeys, k.length);
			await applyWriteOps(db, [
				{ op: "delete", model: "sessions", where: eqWhere("userId", userId) },
				{ op: "delete", model: "apiKeys", where: eqWhere("userId", userId) },
			]);
		},
		// 2: delete mode removes the agents later, so revoked links move to tombstone agents first
		async () => {
			if (keep || agentIds.length === 0) return;
			const links = await db
				.select({ id: delegationChains.id })
				.from(delegationChains)
				.where(
					or(
						inArray(delegationChains.fromAgentId, agentIds),
						inArray(delegationChains.toAgentId, agentIds),
					),
				);
			if (links.length === 0) return;
			await ensureTombstoneUser(db, anonUserId);
			const ops: WriteOp[] = [];
			for (const agentId of agentIds) {
				await ensureTombstoneAgent(db, anonAgent(agentId), anonUserId);
				ops.push(
					{
						op: "update",
						model: "delegationChains",
						where: eqWhere("fromAgentId", agentId),
						set: { fromAgentId: anonAgent(agentId) },
					},
					{
						op: "update",
						model: "delegationChains",
						where: eqWhere("toAgentId", agentId),
						set: { toAgentId: anonAgent(agentId) },
					},
				);
			}
			await applyWriteOps(db, ops);
		},
		// 3: audit identity (tombstones, erasure record, per agent rewrites)
		async () => {
			const n = await eraseAuditIdentity(db, {
				userId,
				agentIds,
				anonUserId,
				anonAgentId: anonAgent,
				keepRows: keep,
			});
			m.counts.anonymizedAuditLogs = Math.max(m.counts.anonymizedAuditLogs, n);
		},
		// 4: delete mode also blanks accountability ids on other people's rows
		async () => {
			if (keep) return;
			const ops: WriteOp[] = [
				{
					op: "update",
					model: "auditLogs",
					where: eqWhere("subjectId", userId),
					set: { subjectId: null },
				},
				{
					op: "update",
					model: "auditLogs",
					where: eqWhere("approverId", userId),
					set: { approverId: null },
				},
				{
					op: "update",
					model: "auditLogs",
					where: eqWhere("actorId", userId),
					set: { actorId: null },
				},
			];
			if (agentIds.length > 0) {
				ops.push({
					op: "update",
					model: "auditLogs",
					where: [{ field: "actorId", op: "in", value: agentIds }],
					set: { actorId: null },
				});
			}
			await applyWriteOps(db, ops);
		},
		// 5: personal rows keyed by the user id or email (the user row still exists, so the email is readable)
		async () => {
			const approvals = await db
				.select({ id: approvalRequests.id })
				.from(approvalRequests)
				.where(eq(approvalRequests.userId, userId));
			const emailRow = await db
				.select({ email: users.email })
				.from(users)
				.where(eq(users.id, userId));
			const email = emailRow[0]?.email;
			const ops: WriteOp[] = [];
			if (approvals.length > 0) {
				ops.push({
					op: "delete",
					model: "approvalVotes",
					where: [{ field: "approvalId", op: "in", value: approvals.map((r) => r.id) }],
				});
			}
			for (const model of [
				"approvalRequests",
				"budgetPolicies",
				"oauthAccessTokens",
				"oauthAuthorizationCodes",
				"totpRecords",
				"passkeyCredentials",
				"orgMembers",
			] as const) {
				ops.push({ op: "delete", model, where: eqWhere("userId", userId) });
			}
			if (email) {
				ops.push(
					{ op: "delete", model: "magicLinks", where: eqWhere("email", email) },
					{ op: "delete", model: "emailOtps", where: eqWhere("email", email) },
				);
			}
			await applyWriteOps(db, ops);
		},
		// 6: organizations owned by the user (only when asked), each as one atomic group
		async () => {
			if (!m.deleteOrganizations) return;
			const orgs = await db
				.select({ id: organizations.id })
				.from(organizations)
				.where(eq(organizations.ownerId, userId));
			for (const org of orgs) await applyWriteOps(db, orgRemoveOps(org.id));
		},
		// 7: rows that outlive the user move to the tombstone user so the FKs hold once the user is gone
		async () => {
			await ensureTombstoneUser(db, anonUserId);
			const ops: WriteOp[] = [];
			const owner = (
				model: "agents" | "organizations" | "agentRegistrationTokens" | "ephemeralSessions",
			) =>
				ops.push({
					op: "update",
					model,
					where: eqWhere("ownerId", userId),
					set: { ownerId: anonUserId },
				});
			if (agentIds.length > 0) {
				if (keep) owner("agents");
				else ops.push({ op: "delete", model: "agents", where: eqWhere("ownerId", userId) });
			}
			owner("organizations");
			ops.push({
				op: "update",
				model: "orgInvitations",
				where: eqWhere("invitedBy", userId),
				set: { invitedBy: anonUserId },
			});
			owner("agentRegistrationTokens");
			owner("ephemeralSessions");
			await applyWriteOps(db, ops);
		},
		// 8: the user row, last
		async () => {
			await db.delete(users).where(eq(users.id, userId));
		},
	];

	for (let i = m.completed; i < steps.length; i++) {
		await steps[i]?.();
		m.completed = i + 1;
		await saveErasureMarker(db, anonUserId, m);
	}
	m.done = true;
	m.agentIds = [];
	await saveErasureMarker(db, anonUserId, m);
	return resultOf(m);
}
