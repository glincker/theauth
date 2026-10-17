import type { createAgentModule } from "../agent/agent.js";
import type { createDelegationModule } from "../delegation/delegation.js";
import type { TheAuthHooks } from "../hooks/lifecycle.js";
import { DECISION_CODES, violationTypeOf } from "../permission/codes.js";
import type { createPermissionEngine } from "../permission/engine.js";
import type { AuthorizeRequest, AuthorizeResult, RequestContext } from "../types.js";

export interface AuthorizePipelineDeps {
	hooks: TheAuthHooks;
	agentModule: ReturnType<typeof createAgentModule>;
	permissionEngine: ReturnType<typeof createPermissionEngine>;
	delegationModule: ReturnType<typeof createDelegationModule>;
}

export interface AuthorizePipeline {
	authorize(
		agentId: string,
		request: AuthorizeRequest,
		context?: RequestContext,
	): Promise<AuthorizeResult>;
	authorizeByToken(
		token: string,
		request: AuthorizeRequest,
		context?: RequestContext,
	): Promise<AuthorizeResult>;
}

export function createAuthorizePipeline(deps: AuthorizePipelineDeps): AuthorizePipeline {
	const { hooks, agentModule, permissionEngine, delegationModule } = deps;

	async function authorize(
		agentId: string,
		request: AuthorizeRequest,
		context?: RequestContext,
	): Promise<AuthorizeResult> {
		if (hooks.beforeAuthorize) {
			const verdict = await hooks.beforeAuthorize({
				agentId,
				action: request.action,
				resource: request.resource,
				arguments: request.arguments,
			});
			if (verdict && !verdict.allow) {
				const reason = verdict.reason ?? "Blocked by beforeAuthorize hook";
				void hooks.onViolation?.({
					type: violationTypeOf(DECISION_CODES.HOOK_DENIED),
					code: DECISION_CODES.HOOK_DENIED,
					agentId,
					action: request.action,
					resource: request.resource,
					reason,
				});
				return { allowed: false, reason, auditId: "", code: DECISION_CODES.HOOK_DENIED };
			}
		}

		const agent = await agentModule.get(agentId);
		if (!agent) {
			return {
				allowed: false,
				reason: `Agent "${agentId}" not found`,
				auditId: "",
				code: DECISION_CODES.AGENT_NOT_FOUND,
			};
		}
		if (agent.status !== "active") {
			const code =
				agent.status === "expired" ? DECISION_CODES.AGENT_EXPIRED : DECISION_CODES.AGENT_REVOKED;
			const auditId = await permissionEngine.recordDenial(
				{ agentId: agent.id, ownerId: agent.ownerId },
				context ? { ...request, context } : request,
				code,
			);
			return {
				allowed: false,
				reason: `Agent "${agent.name}" is ${agent.status}`,
				auditId,
				code,
			};
		}

		const enrichedRequest: AuthorizeRequest = context ? { ...request, context } : request;

		// Denial rows are deferred: a delegated fallback may overturn this denial,
		// and writing one row per path would orphan the first auditId.
		const ownResult = await permissionEngine.authorize(agent, enrichedRequest, {
			deferDenialAudit: true,
		});

		let finalResult: AuthorizeResult;

		if (ownResult.allowed) {
			finalResult = ownResult;
		} else {
			const delegatedPerms = await delegationModule.getEffectivePermissions(agentId);

			if (delegatedPerms.length === 0) {
				finalResult = ownResult;
			} else {
				const agentWithDelegated = { ...agent, permissions: delegatedPerms };
				const delegatedResult = await permissionEngine.authorize(
					agentWithDelegated,
					enrichedRequest,
					{ deferDenialAudit: true },
				);
				// Both denied: keep the original denial, unless an approval failure is more specific.
				const approvalDenied =
					delegatedResult.code === DECISION_CODES.APPROVAL_INVALID ||
					delegatedResult.code === DECISION_CODES.APPROVAL_REQUIRED;
				finalResult = delegatedResult.allowed || approvalDenied ? delegatedResult : ownResult;
			}
		}

		// One row for the final denial; allowed results were already written.
		if (!finalResult.allowed) {
			await permissionEngine.auditDenial(agent, enrichedRequest, finalResult);
		}

		// Fire-and-forget: a throwing hook must not change the authorization result.
		void Promise.resolve()
			.then(() =>
				hooks.afterAuthorize?.({
					agentId,
					action: request.action,
					resource: request.resource,
					result: {
						allowed: finalResult.allowed,
						reason: finalResult.reason,
						auditId: finalResult.auditId,
						code: finalResult.code,
					},
				}),
			)
			.catch(() => {
				// Hook failures are the caller's concern; the SDK has no logger to report to.
			});

		if (!finalResult.allowed) {
			const code = finalResult.code ?? DECISION_CODES.NO_PERMISSION;
			void Promise.resolve()
				.then(() =>
					hooks.onViolation?.({
						type: violationTypeOf(code),
						code,
						agentId,
						action: request.action,
						resource: request.resource,
						reason: finalResult.reason ?? "Authorization denied",
					}),
				)
				.catch(() => {});
		}

		return finalResult;
	}

	async function authorizeByToken(
		token: string,
		request: AuthorizeRequest,
		context?: RequestContext,
	): Promise<AuthorizeResult> {
		const { agent, rejected } = await agentModule.resolveToken(token);
		if (!agent) {
			// A token that belongs to a known revoked or expired agent is recorded.
			// An unknown token has no agent to attach a row to and is not.
			const auditId = rejected
				? await permissionEngine.recordDenial(
						rejected,
						context ? { ...request, context } : request,
						rejected.reason === "expired"
							? DECISION_CODES.AGENT_EXPIRED
							: DECISION_CODES.AGENT_REVOKED,
					)
				: "";
			return {
				allowed: false,
				reason: "Invalid or expired agent token",
				auditId,
				code: DECISION_CODES.INVALID_TOKEN,
			};
		}
		const enrichedRequest: AuthorizeRequest = context ? { ...request, context } : request;
		return permissionEngine.authorize(agent, enrichedRequest);
	}

	return { authorize, authorizeByToken };
}
