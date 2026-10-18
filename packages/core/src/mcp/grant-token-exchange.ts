import { decodeJwt, decodeProtectedHeader } from "jose";
import {
	bindingActorMapper,
	bindingStoreOf,
	earliest,
	MCP_BINDING_NOT_ENTITLED,
	readBindingClaim,
	readParentJtis,
	requireBoundChain,
	resolveExchangeBinding,
} from "./binding.js";
import type { GrantClientAuth } from "./grant-common.js";
import { authenticateGrantClient, narrowScopes } from "./grant-common.js";
import {
	DEFAULT_MAX_CHAIN_DEPTH,
	GRANT_TYPE_TOKEN_EXCHANGE,
	TOKEN_TYPE_ACCESS_TOKEN,
} from "./grant-types.js";
import { canonicalizeResource, configuredResources } from "./lenient.js";
import type { McpDelegationBinding, McpMintBinding } from "./revocation-types.js";
import {
	MCP_DELEGATION_CLAIM,
	MCP_PARENT_JTI_CLAIM,
	MCP_PARENT_JTI_MAX,
} from "./revocation-types.js";
import type { McpAgentClaims } from "./token-issue.js";
import { issueGrantToken, MCP_BINDING_REFUSED } from "./token-issue.js";
import type {
	McpActorClaim,
	McpAuthContext,
	McpSession,
	McpTokenResponse,
	Result,
} from "./types.js";
import { validateAccessToken } from "./validate.js";

/**
 * RFC 8693 token exchange for access tokens issued by this server.
 * Rules enforced here:
 * - the subject token (and actor token, when sent) must verify as an access token we issued, be unexpired and not be on the jti denylist;
 * - a DPoP-bound token can only be exchanged with a proof from the same key;
 * - scopes can narrow, never widen;
 * - the audience can change only to a configured resource;
 * - the new token never outlives the subject token, the actor token, any bound delegation link or any bound agent;
 * - the result carries a nested `act` claim (RFC 8693 section 4.1), capped at `maxChainDepth`;
 * - when a binding store is attached, the result also carries the signed `theauth_dlg` binding to the
 *   exact delegation rows and agents its authority rests on (refused when a link is missing, revoked
 *   or expired, an agent is dead, or the actor mapper throws). With no agent on the path the token is
 *   unbound (only jti, subject and client revocation apply) unless `revocation.requireBoundChain`;
 * - the subject token's user must own, or be delegated through the chain to, every agent the child
 *   names (an `invalid_grant` plus an audit row under the refused agent otherwise);
 * - the child's `agent_id` is the acting agent, the last entry of `theauth_dlg.agt`;
 * - the child carries its subject lineage in `theauth_pjti`, so revoking any ancestor token denies it;
 * - exchanged tokens never carry a refresh token.
 */

interface VerifiedToken {
	session: McpSession;
	act: McpActorClaim | undefined;
	agent: { agentId?: string; agentType?: string; trustTier?: string } | undefined;
	/** The verified `theauth_dlg`, when the token is bound. */
	binding: McpDelegationBinding | undefined;
	/** The verified `theauth_pjti` (ancestor jtis, root first), empty for a token minted by a grant. */
	parents: string[];
}

function grantError(message: string): Result<never> {
	return { success: false, error: { code: "INVALID_GRANT", message } };
}

/** Verify a token this server issued, as a subject or actor token. */
async function verifyOwnToken(
	ctx: McpAuthContext,
	token: string,
	proofJkt: string | null,
	label: string,
): Promise<Result<VerifiedToken>> {
	let typ: string | undefined;
	let claims: ReturnType<typeof decodeJwt>;
	try {
		typ = decodeProtectedHeader(token).typ;
		claims = decodeJwt(token);
	} catch {
		return grantError(`${label} is not a valid access token`);
	}
	if (typ !== "at+jwt") return grantError(`${label} is not an access token issued by this server`);
	const aud = Array.isArray(claims.aud) ? claims.aud[0] : claims.aud;
	if (typeof aud !== "string") return grantError(`${label} has no audience`);
	const cnf = claims.cnf as { jkt?: unknown } | undefined;
	const bound = typeof cnf?.jkt === "string";

	// The audience read above only selects which value to verify against; the
	// signature and issuer checks make it trustworthy.
	// The token endpoint always checks revocation and the binding live, whatever the resource mode.
	const result = await validateAccessToken(ctx, token, {
		expectedAudience: aud,
		presentedDpopJkt: bound ? proofJkt : null,
		freshness: "live",
	});
	if (!result.success) return grantError(`${label} is not valid: ${result.error.message}`);
	// Read only now that the signature verified: the claim is never trusted from anywhere else.
	const binding = result.data.binding ?? readBindingClaim(claims[MCP_DELEGATION_CLAIM]);
	if (binding === null) return grantError(`${label} has a malformed delegation binding`);
	const parents = readParentJtis(claims[MCP_PARENT_JTI_CLAIM]);
	if (parents === null) return grantError(`${label} has a malformed parent token list`);

	const act = claims.act as McpActorClaim | undefined;
	const agentId = typeof claims.agent_id === "string" ? claims.agent_id : undefined;
	const agentType = typeof claims.agent_type === "string" ? claims.agent_type : undefined;
	const trustTier = typeof claims.trust_tier === "string" ? claims.trust_tier : undefined;
	const hasAgent = agentId !== undefined || agentType !== undefined || trustTier !== undefined;
	return {
		success: true,
		data: {
			session: result.data,
			act: typeof act === "object" && act !== null ? act : undefined,
			agent: hasAgent
				? {
						...(agentId !== undefined ? { agentId } : {}),
						...(agentType !== undefined ? { agentType } : {}),
						...(trustTier !== undefined ? { trustTier } : {}),
					}
				: undefined,
			binding,
			parents: parents ?? [],
		},
	};
}

function chainDepth(act: McpActorClaim | undefined): number {
	let depth = 0;
	let node: McpActorClaim | undefined = act;
	while (typeof node === "object" && node !== null && depth < 64) {
		depth += 1;
		node = node.act;
	}
	return depth;
}

export interface TokenExchangeParams {
	client_id: string;
	subject_token: string;
	subject_token_type: string;
	actor_token?: string | undefined;
	actor_token_type?: string | undefined;
	requested_token_type?: string | undefined;
	scope?: string | undefined;
	resource?: string | undefined;
	audience?: string | undefined;
}

export async function handleTokenExchangeGrant(
	ctx: McpAuthContext,
	data: TokenExchangeParams,
	auth: GrantClientAuth,
	proofJkt: string | null,
): Promise<Result<McpTokenResponse>> {
	const config = ctx.config.tokenExchange;
	if (!config?.enabled) {
		return {
			success: false,
			error: { code: "UNSUPPORTED_GRANT_TYPE", message: "Token exchange is not enabled" },
		};
	}

	const authenticated = await authenticateGrantClient(
		ctx,
		data.client_id,
		GRANT_TYPE_TOKEN_EXCHANGE,
		auth,
	);
	if (!authenticated.success) return authenticated;
	const client = authenticated.data;

	// Token types: only access tokens we issued
	if (data.subject_token_type !== TOKEN_TYPE_ACCESS_TOKEN) {
		return {
			success: false,
			error: { code: "INVALID_REQUEST", message: "subject_token_type must be an access_token" },
		};
	}
	if (data.actor_token !== undefined && data.actor_token_type !== TOKEN_TYPE_ACCESS_TOKEN) {
		return {
			success: false,
			error: { code: "INVALID_REQUEST", message: "actor_token_type must be an access_token" },
		};
	}
	if (
		data.requested_token_type !== undefined &&
		data.requested_token_type !== TOKEN_TYPE_ACCESS_TOKEN
	) {
		return {
			success: false,
			error: { code: "INVALID_REQUEST", message: "Only access_token can be requested" },
		};
	}
	if (
		data.resource !== undefined &&
		data.audience !== undefined &&
		data.resource !== data.audience
	) {
		return {
			success: false,
			error: { code: "INVALID_TARGET", message: "resource and audience must not differ" },
		};
	}

	const subject = await verifyOwnToken(ctx, data.subject_token, proofJkt, "subject_token");
	if (!subject.success) return subject;
	let actorSession: McpSession | null = null;
	let actorBinding: McpDelegationBinding | undefined;
	if (data.actor_token !== undefined) {
		const actor = await verifyOwnToken(ctx, data.actor_token, proofJkt, "actor_token");
		if (!actor.success) return actor;
		actorSession = actor.data.session;
		actorBinding = actor.data.binding;
	}
	const subjectSession = subject.data.session;

	// Scope: narrowing only
	const scopes = narrowScopes(ctx, data.scope, subjectSession.scopes);
	if (!scopes.success) return scopes;

	// Audience: unchanged, or another configured resource
	const requestedTarget = data.resource ?? data.audience;
	let resource = subjectSession.resource;
	if (requestedTarget !== undefined) {
		const canonical = canonicalizeResource(ctx, requestedTarget);
		if (canonical !== subjectSession.resource && !configuredResources(ctx).includes(canonical)) {
			return {
				success: false,
				error: {
					code: "INVALID_TARGET",
					message: "Token exchange can only target a configured resource",
				},
			};
		}
		resource = canonical;
	}

	const maxDepth = config.maxChainDepth ?? DEFAULT_MAX_CHAIN_DEPTH;
	const actorSub = actorSession?.userId ?? client.clientId;
	const actorClientId = actorSession?.clientId ?? client.clientId;
	const act: McpActorClaim = {
		sub: actorSub,
		client_id: actorClientId,
		...(subject.data.act ? { act: subject.data.act } : {}),
	};
	if (chainDepth(act) > maxDepth) {
		return {
			success: false,
			error: {
				code: "INVALID_REQUEST",
				message: `Delegation chain would exceed the maximum depth of ${maxDepth}`,
			},
		};
	}

	const now = new Date();
	const parentJtis = [...subject.data.parents, subjectSession.tokenId];
	if (parentJtis.length > MCP_PARENT_JTI_MAX) {
		return grantError("subject_token has too many ancestors to exchange again");
	}

	const minted = await mintBinding(ctx, {
		subject: subject.data,
		actor: { sub: actorSub, clientId: actorClientId },
		actorBinding,
		clientId: client.clientId,
		now,
	});
	if (!minted.success) return minted;
	const binding = minted.data.binding;

	if (config.authorize) {
		const allowed = await config.authorize({
			client,
			subject: {
				userId: subjectSession.userId,
				clientId: subjectSession.clientId,
				scopes: subjectSession.scopes,
				resource: subjectSession.resource,
			},
			actor: actorSession ? { userId: actorSession.userId, clientId: actorSession.clientId } : null,
			scopes: scopes.data,
			resource,
			...(binding ? { binding } : {}),
		});
		if (!allowed) {
			return {
				success: false,
				error: { code: "ACCESS_DENIED", message: "Token exchange was refused by policy" },
			};
		}
	}

	// Lifetime: min(accessTokenTtl, subject exp, actor token exp, every bound link and agent expiry)
	const notAfter = earliest(
		subjectSession.expiresAt,
		actorSession?.expiresAt,
		minted.data.capAt,
	) as Date;
	const remaining = Math.floor(notAfter.getTime() / 1000) - Math.floor(Date.now() / 1000);
	if (remaining < 1) return grantError("subject_token or its delegation is about to expire");

	try {
		const response = await issueGrantToken(ctx, {
			userId: subjectSession.userId,
			clientId: client.clientId,
			scopes: scopes.data,
			resource,
			dpopJkt: proofJkt,
			options: {
				ttlSeconds: Math.min(ctx.config.accessTokenTtl, remaining),
				expiresNotAfter: notAfter,
				act,
				binding: binding ?? null,
				agent: childAgent(binding, subject.data.agent),
				inheritClientAgent: false,
				parentJtis,
			},
			issuedTokenType: TOKEN_TYPE_ACCESS_TOKEN,
		});
		return { success: true, data: response };
	} catch (error) {
		if (error instanceof Error && error.name === MCP_BINDING_REFUSED) {
			return grantError(error.message);
		}
		throw error;
	}
}

/**
 * Agent claims of the child. Bound: the acting agent, the last entry of `agt` (the principal that
 * acts; the root and every hop stay in `theauth_dlg`), with the subject's type and trust tier only
 * when it is the same agent. Unbound: the subject's own agent claims, if any.
 */
function childAgent(
	binding: McpDelegationBinding | undefined,
	subjectAgent: VerifiedToken["agent"],
): McpAgentClaims {
	const acting = binding?.agt[binding.agt.length - 1];
	if (acting === undefined) return { ...(subjectAgent ?? {}) };
	if (subjectAgent?.agentId !== acting) return { agentId: acting };
	return { ...subjectAgent, agentId: acting };
}

/**
 * Resolve the child's delegation binding. Without an attached binding store nothing changes from
 * before bindings existed (unbound, no mapper calls), except that `requireBoundChain` refuses.
 * An actor token that is itself bound must be live too; its authority is not merged into the child.
 */
async function mintBinding(
	ctx: McpAuthContext,
	input: {
		subject: VerifiedToken;
		actor: { sub: string; clientId: string };
		actorBinding: McpDelegationBinding | undefined;
		clientId: string;
		now: Date;
	},
): Promise<Result<McpMintBinding>> {
	const required = requireBoundChain(ctx);
	const store = bindingStoreOf(ctx);
	if (!store) {
		if (required) return grantError("Token exchange requires a delegation binding store");
		return { success: true, data: { capAt: null } };
	}
	if (input.actorBinding) {
		const verdict = await store.check(input.actorBinding, input.now).catch(() => null);
		if (verdict === null) {
			return {
				success: false,
				error: { code: "SERVER_ERROR", message: "Delegation binding could not be checked" },
			};
		}
		if (!verdict.live)
			return grantError(`actor_token delegation is no longer live (${verdict.reason})`);
	}
	const { session, act, agent, binding } = input.subject;
	const resolved = await resolveExchangeBinding(store, bindingActorMapper(ctx), {
		...(binding ? { parent: binding } : {}),
		subject: session.userId,
		...(act ? { act } : {}),
		...(agent?.agentId ? { subjectAgentId: agent.agentId } : {}),
		actor: input.actor,
		requireBoundChain: required,
		now: input.now,
	});
	const foreign = resolved.success ? undefined : resolved.error.details?.[MCP_BINDING_NOT_ENTITLED];
	if (!resolved.success && typeof foreign === "string" && store.auditDenial) {
		const agt = resolved.error.details?.agt;
		await store
			.auditDenial({
				agentId: foreign,
				subject: session.userId,
				clientId: input.clientId,
				agt: Array.isArray(agt) ? agt.filter((x): x is string => typeof x === "string") : [],
				reason: "token exchange refused: subject not entitled to agent",
			})
			.catch(() => undefined);
	}
	return resolved;
}
