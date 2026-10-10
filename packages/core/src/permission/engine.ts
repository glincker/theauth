import { insertAuditRow } from "../audit/chain.js";
import { generateId } from "../crypto/web-crypto.js";
import type { Database } from "../db/database.js";
import { evaluateConstraints, findMatchingPermission } from "../policy/abac.js";
import type { AgentIdentity, AuthorizeRequest, AuthorizeResult } from "../types.js";

interface PermissionEngineConfig {
	db: Database;
	auditAll: boolean;
}

/**
 * Create the permission/authorization engine.
 *
 * This remains the public entry point used by adapters. The constraint and
 * matching primitives now live in policy/abac.ts so the new unified policy
 * engine can reuse them. A follow-on patch rewires this function to delegate
 * to policy/engine.ts; today it still performs direct-permission evaluation.
 */
export function createPermissionEngine(config: PermissionEngineConfig) {
	const { db, auditAll } = config;

	async function authorize(
		agent: AgentIdentity,
		request: AuthorizeRequest,
	): Promise<AuthorizeResult> {
		const startTime = performance.now();
		const auditId = generateId();

		const matchingPermission = findMatchingPermission(
			agent.permissions,
			request.action,
			request.resource,
		)?.permission;

		if (!matchingPermission) {
			const result: AuthorizeResult = {
				allowed: false,
				reason: `No permission grants agent "${agent.name}" access to "${request.action}" on "${request.resource}"`,
				auditId,
			};
			if (auditAll) {
				await writeAuditLog(db, agent, request, result, startTime, auditId);
			}
			return result;
		}

		if (matchingPermission.constraints) {
			const constraintResult = await evaluateConstraints(
				db,
				{
					subjectId: agent.id,
					resource: request.resource,
					arguments: request.arguments,
					// Adapters pass the client IP via context; direct callers may set request.ip.
					ip: request.context?.ip ?? request.ip,
				},
				matchingPermission.constraints,
			);
			if (!constraintResult.allowed) {
				const result: AuthorizeResult = {
					allowed: false,
					reason: constraintResult.reason,
					auditId,
				};
				if (auditAll) {
					await writeAuditLog(db, agent, request, result, startTime, auditId);
				}
				return result;
			}
		}

		const result: AuthorizeResult = { allowed: true, auditId };
		if (auditAll) {
			await writeAuditLog(db, agent, request, result, startTime, auditId);
		}
		return result;
	}

	/**
	 * Record a denial that happened before permission evaluation, such as a
	 * revoked or expired agent. Respects `auditAll` and goes through the same
	 * writer, so the agent's hash chain stays valid.
	 *
	 * Never throws: a failed audit write must not turn a denial into an
	 * exception. On failure the denial stands and `auditId` is empty, meaning
	 * no row was written.
	 */
	async function recordDenial(
		target: { agentId: string; ownerId: string },
		request: AuthorizeRequest,
		reasonCode: DenialReasonCode,
	): Promise<string> {
		if (!auditAll) return "";
		const auditId = generateId();
		try {
			await insertAuditRow(db, {
				id: auditId,
				agentId: target.agentId,
				userId: target.ownerId,
				action: request.action,
				resource: request.resource,
				parameters: request.arguments ?? {},
				result: "denied",
				reason: reasonCode,
				durationMs: 0,
				timestamp: new Date(),
				ip: request.context?.ip ?? request.ip ?? null,
				userAgent: request.context?.userAgent ?? null,
			});
			return auditId;
		} catch {
			return "";
		}
	}

	return { authorize, recordDenial };
}

/** Stable reason codes stored on audit rows for denials made before permission evaluation. */
export type DenialReasonCode = "agent_revoked" | "agent_expired";

async function writeAuditLog(
	db: Database,
	agent: AgentIdentity,
	request: AuthorizeRequest,
	result: AuthorizeResult,
	startTime: number,
	auditId: string,
): Promise<void> {
	const durationMs = Math.round(performance.now() - startTime);

	await insertAuditRow(db, {
		id: auditId,
		agentId: agent.id,
		userId: agent.ownerId,
		action: request.action,
		resource: request.resource,
		parameters: request.arguments ?? {},
		result: result.allowed ? "allowed" : "denied",
		reason: result.reason ?? null,
		durationMs,
		timestamp: new Date(),
		ip: request.context?.ip ?? request.ip ?? null,
		userAgent: request.context?.userAgent ?? null,
	});
}
