import { generateId } from "../crypto/web-crypto.js";
import type { Database } from "../db/database.js";
import { auditLogs } from "../db/schema.js";
import { evaluateConstraints, matchAction, matchResource } from "../policy/abac.js";
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

		const matchingPermission = agent.permissions.find(
			(p) => matchResource(p.resource, request.resource) && matchAction(p.actions, request.action),
		);

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
					ip: request.ip,
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

	return { authorize };
}

async function writeAuditLog(
	db: Database,
	agent: AgentIdentity,
	request: AuthorizeRequest,
	result: AuthorizeResult,
	startTime: number,
	auditId: string,
): Promise<void> {
	const durationMs = Math.round(performance.now() - startTime);

	await db.insert(auditLogs).values({
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
		ip: request.context?.ip ?? null,
		userAgent: request.context?.userAgent ?? null,
	});
}
