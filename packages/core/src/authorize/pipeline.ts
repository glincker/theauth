import type { createAgentModule } from "../agent/agent.js";
import type { Database } from "../db/database.js";
import type { createDelegationModule } from "../delegation/delegation.js";
import { resolveHookChain } from "../delegation/lineage.js";
import type { AuthorizeSource, HookDelegationChain, TheAuthHooks } from "../hooks/lifecycle.js";
import type { BeforeAuthorizeRunner } from "../hooks/run.js";
import { DECISION_CODES, violationTypeOf } from "../permission/codes.js";
import type { createPermissionEngine } from "../permission/engine.js";
import type { AgentIdentity, AuthorizeRequest, AuthorizeResult, RequestContext } from "../types.js";
import type { HookBlock } from "./hook-outcome.js";
import { hookAuditDetail, isHookBlock, withHookDetail } from "./hook-outcome.js";

export interface AuthorizePipelineDeps {
	db: Database;
	hooks: TheAuthHooks;
	agentModule: ReturnType<typeof createAgentModule>;
	permissionEngine: ReturnType<typeof createPermissionEngine>;
	delegationModule: ReturnType<typeof createDelegationModule>;
	/** Runs `hooks.beforeAuthorize` with timeout and fail-closed handling. */
	runBeforeAuthorize: BeforeAuthorizeRunner;
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
	const { db, hooks, agentModule, permissionEngine, delegationModule, runBeforeAuthorize } = deps;

	async function authorize(
		agentId: string,
		request: AuthorizeRequest,
		context?: RequestContext,
	): Promise<AuthorizeResult> {
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

		return authorizeResolved(agent, request, context, "authorize");
	}

	/** Everything after the agent is resolved and active: hook, own permissions, delegated fallback, audit, notifications. */
	async function authorizeResolved(
		agent: AgentIdentity,
		request: AuthorizeRequest,
		context: RequestContext | undefined,
		source: AuthorizeSource,
	): Promise<AuthorizeResult> {
		const agentId = agent.id;
		const enrichedRequest: AuthorizeRequest = context ? { ...request, context } : request;

		// Lineage is loaded lazily and only when a hook is configured.
		let chain: Promise<HookDelegationChain> | undefined;
		const loadChain = () => {
			chain ??= resolveHookChain(db, agentId);
			return chain;
		};
		const { token: _token, ...publicAgent } = agent;
		const outcome = await runBeforeAuthorize({
			agentId,
			action: request.action,
			resource: request.resource,
			arguments: request.arguments,
			agent: publicAgent,
			source,
			context,
			dryRun: false,
			delegation: loadChain,
		});
		if (isHookBlock(outcome)) {
			return blockedByHook(agent, enrichedRequest, outcome, source, await loadChain());
		}
		const hookDetail = hookAuditDetail(outcome);
		const auditParameters = hookDetail ? { theauthHook: hookDetail } : undefined;

		// Denial rows are deferred: a delegated fallback may overturn this denial,
		// and writing one row per path would orphan the first auditId.
		const ownResult = await permissionEngine.authorize(agent, enrichedRequest, {
			deferDenialAudit: true,
			auditParameters,
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
					{ deferDenialAudit: true, auditParameters },
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
			await permissionEngine.auditDenial(agent, enrichedRequest, finalResult, auditParameters);
		}

		// Fire-and-forget: a throwing hook must not change the authorization result.
		void Promise.resolve()
			.then(() =>
				hooks.afterAuthorize?.({
					agentId,
					action: request.action,
					resource: request.resource,
					source,
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
						source,
						reason: finalResult.reason ?? "Authorization denied",
					}),
				)
				.catch(() => {});
		}

		return finalResult;
	}

	/** Write the audit row for a hook block, notify, and shape the result. The row joins the agent's hash chain. */
	async function blockedByHook(
		agent: AgentIdentity,
		request: AuthorizeRequest,
		outcome: HookBlock,
		source: AuthorizeSource,
		chain: HookDelegationChain,
	): Promise<AuthorizeResult> {
		const auditId = await permissionEngine.recordDenial(
			{ agentId: agent.id, ownerId: agent.ownerId },
			request,
			outcome.code,
			{
				parameters: withHookDetail(request.arguments, hookAuditDetail(outcome)),
				durationMs: outcome.elapsedMs,
				subjectId: chain.rootOwnerId,
				actorId: agent.id,
				delegationChain: chain.path.length > 1 ? chain.path : undefined,
				result: outcome.kind === "escalate" ? "escalated" : "denied",
				reason: outcome.reason,
			},
		);
		void Promise.resolve()
			.then(() =>
				hooks.onViolation?.({
					type: violationTypeOf(outcome.code),
					code: outcome.code,
					agentId: agent.id,
					action: request.action,
					resource: request.resource,
					source,
					reason: outcome.reason,
				}),
			)
			.catch(() => {});
		return { allowed: false, reason: outcome.reason, auditId, code: outcome.code };
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
		return authorizeResolved(agent, request, context, "authorizeByToken");
	}

	return { authorize, authorizeByToken };
}
