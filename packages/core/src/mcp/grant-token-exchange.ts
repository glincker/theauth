import { decodeJwt, decodeProtectedHeader } from "jose";
import type { GrantClientAuth } from "./grant-common.js";
import { authenticateGrantClient, narrowScopes } from "./grant-common.js";
import {
	DEFAULT_MAX_CHAIN_DEPTH,
	GRANT_TYPE_TOKEN_EXCHANGE,
	TOKEN_TYPE_ACCESS_TOKEN,
} from "./grant-types.js";
import { canonicalizeResource, configuredResources } from "./lenient.js";
import { issueGrantToken } from "./token-issue.js";
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
 * - the new token never outlives the subject token;
 * - the result carries a nested `act` claim, capped at `maxChainDepth`.
 */

interface VerifiedToken {
	session: McpSession;
	act: McpActorClaim | undefined;
	agent: { agentId?: string; agentType?: string; trustTier?: string } | undefined;
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
	const result = await validateAccessToken(ctx, token, {
		expectedAudience: aud,
		presentedDpopJkt: bound ? proofJkt : null,
	});
	if (!result.success) return grantError(`${label} is not valid: ${result.error.message}`);

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
	if (data.actor_token !== undefined) {
		const actor = await verifyOwnToken(ctx, data.actor_token, proofJkt, "actor_token");
		if (!actor.success) return actor;
		actorSession = actor.data.session;
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
		});
		if (!allowed) {
			return {
				success: false,
				error: { code: "ACCESS_DENIED", message: "Token exchange was refused by policy" },
			};
		}
	}

	// Lifetime never exceeds the subject token's
	const remaining = Math.floor((subjectSession.expiresAt.getTime() - Date.now()) / 1000);
	if (remaining < 1) return grantError("subject_token is about to expire");

	const response = await issueGrantToken(ctx, {
		userId: subjectSession.userId,
		clientId: client.clientId,
		scopes: scopes.data,
		resource,
		dpopJkt: proofJkt,
		options: {
			ttlSeconds: Math.min(ctx.config.accessTokenTtl, remaining),
			act,
			...(subject.data.agent ? { agent: subject.data.agent } : {}),
		},
		issuedTokenType: TOKEN_TYPE_ACCESS_TOKEN,
	});
	return { success: true, data: response };
}
