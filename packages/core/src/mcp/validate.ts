import { readParentJtis } from "./binding.js";
import { checkLiveDelegation } from "./delegation-check.js";
import type { McpFreshnessSubject } from "./freshness.js";
import {
	checkFreshness,
	freshnessError,
	parseBinding,
	resolveFreshnessSettings,
} from "./freshness.js";
import { verifyAccessJwt } from "./keys.js";
import type { McpFreshnessMode, McpValidateOptions } from "./revocation-types.js";
import { MCP_PARENT_JTI_CLAIM } from "./revocation-types.js";
import type {
	McpActorClaim,
	McpAuthContext,
	McpDelegationHop,
	McpRejectedToken,
	McpSession,
	McpTokenPayload,
	Result,
} from "./types.js";
import { extractBearerToken, timingSafeEqual } from "./utils.js";

const MAX_DELEGATION_DEPTH = 10;

/** Identify a token whose signature verified, for attributing a refusal. Returns undefined when the claims do not name a subject, client and token id. */
function rejectedFrom(claims: unknown): McpRejectedToken | undefined {
	if (typeof claims !== "object" || claims === null) return undefined;
	const c = claims as Record<string, unknown>;
	if (
		typeof c.sub !== "string" ||
		typeof c.client_id !== "string" ||
		typeof c.jti !== "string" ||
		!c.sub ||
		!c.client_id ||
		!c.jti
	) {
		return undefined;
	}
	return {
		clientId: c.client_id,
		subject: c.sub,
		tokenId: c.jti,
		...(typeof c.agent_id === "string" && c.agent_id ? { agentId: c.agent_id } : {}),
	};
}

/** Flatten nested RFC 8693 `act` claims into a list, current actor first. */
function readDelegationChain(act: McpActorClaim | undefined): McpDelegationHop[] {
	const chain: McpDelegationHop[] = [];
	let node: unknown = act;
	while (chain.length < MAX_DELEGATION_DEPTH && typeof node === "object" && node !== null) {
		const { sub, client_id, act: next } = node as McpActorClaim;
		if (typeof sub !== "string") break;
		chain.push({ sub, ...(typeof client_id === "string" ? { clientId: client_id } : {}) });
		node = next;
	}
	return chain;
}

function rejectedDetail(rejected: McpRejectedToken | undefined): Record<string, unknown> {
	return rejected ? { rejected } : {};
}

/**
 * Revocation and binding check for a token whose signature, audience and DPoP key already verified.
 * Succeeds with the time the check ran. A store error is `SERVER_ERROR` (fail closed, never allow).
 * The `theauth_dlg` binding is checked by the freshness layer. The opt in `delegationStore` walk of
 * the `act` chain additionally runs whenever a store is configured, bound token or not: a binding
 * only names the agents resolved at mint time, the walk also maps the subject and actors through
 * the integrator's mapper (a user mapped to a root agent), so it can see links the binding does not.
 */
async function runFreshness(
	ctx: McpAuthContext,
	subject: McpFreshnessSubject,
	chain: McpDelegationHop[],
	mode: McpFreshnessMode,
	rejected: McpRejectedToken | undefined,
): Promise<Result<Date>> {
	const outcome = await checkFreshness(ctx, subject, mode);
	if (!outcome.ok) {
		return { success: false, error: freshnessError(outcome, rejectedDetail(rejected)) };
	}
	if (ctx.config.delegationStore && chain.length > 0) {
		const failure = await checkLiveDelegation(ctx.config.delegationStore, subject.sub, chain, {
			resolveActorAgentId: ctx.config.resolveActorAgentId,
			allowUnmappedActors: ctx.config.allowUnmappedActors,
		}).catch(() => "unavailable" as const);
		if (failure === "unavailable") {
			return {
				success: false,
				error: freshnessError({ ok: false, kind: "unavailable" }, rejectedDetail(rejected)),
			};
		}
		if (failure) {
			const detail =
				failure.reason === "unmapped actor" || failure.reason === "mapper failed"
					? failure.reason
					: `${failure.reason} link`;
			return {
				success: false,
				error: {
					code: "INVALID_TOKEN",
					message: `Delegation chain is no longer valid (${detail})`,
					details: {
						delegation: { from: failure.from, to: failure.to, reason: failure.reason },
						...rejectedDetail(rejected),
					},
				},
			};
		}
	}
	return { success: true, data: outcome.checkedAt };
}

/**
 * Validates an MCP access token (JWT): signature (HS256, or ES256/EdDSA via the JWKS), audience,
 * revocation, scopes, and DPoP binding. A token with `cnf.jkt` is refused unless the caller passes
 * a matching `presentedDpopJkt`, so a bound token never validates as a plain bearer token.
 */
export async function validateAccessToken(
	ctx: McpAuthContext,
	token: string,
	options?: McpValidateOptions,
): Promise<Result<McpSession>> {
	if (!options?.expectedAudience) {
		return {
			success: false,
			error: {
				code: "SERVER_ERROR",
				message:
					"expectedAudience is required. Pass the canonical URI of this resource server " +
					"(or set McpConfig.resource) so tokens issued for other resources are rejected.",
			},
		};
	}
	if (!ctx.config.signingSecret && !ctx.config.signing) {
		return {
			success: false,
			error: {
				code: "SERVER_ERROR",
				message: "MCP signingSecret or signing key is not configured",
			},
		};
	}

	let payload: McpTokenPayload;
	try {
		payload = (await verifyAccessJwt(ctx, token, {
			audience: options.expectedAudience,
		})) as unknown as McpTokenPayload;
	} catch (err) {
		const message = err instanceof Error ? err.message : "Token verification failed";

		// Map jose errors to meaningful error codes
		let code = "INVALID_TOKEN";
		const joseCode = (err as { code?: unknown }).code;
		const claim = (err as { claim?: unknown }).claim;
		if (joseCode === "ERR_JWT_EXPIRED" || message.includes("expired")) {
			code = "TOKEN_EXPIRED";
		} else if (claim === "aud" || message.includes("audience") || message.includes('"aud"')) {
			code = "INVALID_AUDIENCE";
		} else if (claim === "iss" || message.includes("issuer") || message.includes('"iss"')) {
			code = "INVALID_ISSUER";
		}

		// jose attaches the claims to claim validation errors (expired, audience, issuer), and only
		// after the signature verified, so they are safe to attribute. Other failures carry none.
		const rejected = rejectedFrom((err as { payload?: unknown }).payload);
		return {
			success: false,
			error: { code, message, ...(rejected ? { details: { rejected } } : {}) },
		};
	}

	if (!payload.sub || !payload.client_id || !payload.jti) {
		return {
			success: false,
			error: {
				code: "INVALID_TOKEN",
				message: "Token is missing required claims (sub, client_id, jti)",
			},
		};
	}

	const rejected = rejectedFrom(payload);

	// Audience claim must exist (jose already matched it)
	const audience = payload.aud;
	if (!audience) {
		return {
			success: false,
			error: {
				code: "INVALID_AUDIENCE",
				message: "Token has no audience claim. Tokens must be bound to a resource.",
				...(rejected ? { details: { rejected } } : {}),
			},
		};
	}

	// DPoP binding (RFC 9449 section 7)
	const boundJkt = typeof payload.cnf?.jkt === "string" ? payload.cnf.jkt : undefined;
	const presentedJkt = options.presentedDpopJkt ?? undefined;
	if (boundJkt) {
		if (!presentedJkt) {
			return {
				success: false,
				error: {
					code: "INVALID_TOKEN",
					message: "Token is bound to a DPoP key and must be presented with a DPoP proof",
					details: { dpopBound: true, dpopMissing: true, ...(rejected ? { rejected } : {}) },
				},
			};
		}
		if (!timingSafeEqual(boundJkt, presentedJkt)) {
			return {
				success: false,
				error: {
					code: "INVALID_TOKEN",
					message: "DPoP proof key does not match the key the token is bound to",
					details: { dpopBound: true, ...(rejected ? { rejected } : {}) },
				},
			};
		}
	} else if (presentedJkt) {
		return {
			success: false,
			error: {
				code: "INVALID_TOKEN",
				message: "Token is not DPoP-bound, so it cannot be used with the DPoP scheme",
				...(rejected ? { details: { rejected } } : {}),
			},
		};
	}

	// Everything above is cryptographic or in memory. Only now, with signature, issuer, audience,
	// exp and the DPoP key verified, are `theauth_dlg` and `act` trusted and the stores read.
	const binding = parseBinding(payload.theauth_dlg);
	if (binding === null) {
		return {
			success: false,
			error: {
				code: "INVALID_TOKEN",
				message: "Token delegation binding is malformed",
				details: {
					revocation: { reason: "invalid", id: payload.jti },
					...rejectedDetail(rejected),
				},
			},
		};
	}
	// A bound token's agent must be one the binding names (the acting agent), so revoking it always
	// reaches the token. Minting never signs anything else; refuse rather than trust a stray claim.
	const claimedAgent = typeof payload.agent_id === "string" ? payload.agent_id : undefined;
	const parents = readParentJtis(
		(payload as unknown as Record<string, unknown>)[MCP_PARENT_JTI_CLAIM],
	);
	if (
		(binding && claimedAgent !== undefined && !binding.agt.includes(claimedAgent)) ||
		parents === null
	) {
		return {
			success: false,
			error: {
				code: "INVALID_TOKEN",
				message: "Token delegation binding is malformed",
				details: {
					revocation: { reason: "invalid", id: payload.jti },
					...rejectedDetail(rejected),
				},
			},
		};
	}
	const delegationChain = readDelegationChain(payload.act);
	const subject: McpFreshnessSubject = {
		jti: payload.jti,
		sub: payload.sub,
		clientId: payload.client_id,
		iat: typeof payload.iat === "number" ? payload.iat : 0,
		exp: payload.exp,
		...(binding ? { binding } : {}),
		...(!binding && typeof payload.agent_id === "string" && payload.agent_id
			? { agentId: payload.agent_id }
			: {}),
		...(parents ? { parents } : {}),
	};
	const mode = options.freshness ?? resolveFreshnessSettings(ctx).mode;
	const fresh = await runFreshness(ctx, subject, delegationChain, mode, rejected);
	if (!fresh.success) return fresh;

	const tokenScopes = payload.scope ? payload.scope.split(" ") : [];
	const requiredScopes = options?.requiredScopes ?? [];

	for (const required of requiredScopes) {
		if (!tokenScopes.includes(required)) {
			return {
				success: false,
				error: {
					code: "INSUFFICIENT_SCOPE",
					message: `Token is missing required scope: ${required}`,
					details: {
						required: requiredScopes,
						present: tokenScopes,
						...(rejected ? { rejected } : {}),
					},
				},
			};
		}
	}

	const resource = Array.isArray(audience) ? (audience[0] ?? null) : audience;

	const session: McpSession = {
		userId: payload.sub,
		clientId: payload.client_id,
		scopes: tokenScopes,
		resource,
		expiresAt: new Date(payload.exp * 1000),
		tokenId: payload.jti,
		...(boundJkt ? { dpopJkt: boundJkt } : {}),
		...(typeof payload.agent_id === "string"
			? {
					agent: {
						id: payload.agent_id,
						...(typeof payload.agent_type === "string" ? { type: payload.agent_type } : {}),
						...(typeof payload.trust_tier === "string" ? { trustTier: payload.trust_tier } : {}),
					},
				}
			: {}),
		delegationChain,
		...(binding ? { binding } : {}),
		freshness: { mode, checkedAt: fresh.data },
	};
	session.revalidate = async () => {
		if (Date.now() >= payload.exp * 1000) {
			return { success: false, error: { code: "TOKEN_EXPIRED", message: "Token has expired" } };
		}
		const again = await runFreshness(ctx, subject, delegationChain, "live", rejected);
		if (!again.success) return again;
		session.freshness = { mode: "live", checkedAt: again.data };
		return { success: true, data: undefined };
	};

	return { success: true, data: session };
}

/**
 * MCP auth middleware.
 *
 * @example
 * ```typescript
 * const result = await withMcpAuth(ctx, request, { expectedAudience: 'https://mcp.example.com', requiredScopes: ['read'] });
 * if (!result.success) return new Response(JSON.stringify(result.error), { status: 401 });
 * const session = result.data;
 * ```
 */
export async function withMcpAuth(
	ctx: McpAuthContext,
	request: Request,
	options: {
		requiredScopes?: string[];
		/** Canonical URI of this resource server. Required. */
		expectedAudience: string;
	},
): Promise<Result<McpSession>> {
	if (!options?.expectedAudience) {
		return {
			success: false,
			error: {
				code: "SERVER_ERROR",
				message:
					"withMcpAuth requires options.expectedAudience (the canonical URI of this resource server).",
			},
		};
	}

	const token = extractBearerToken(request);

	if (!token) {
		const resourceMetadataUrl = `${ctx.config.baseUrl}/.well-known/oauth-protected-resource`;

		return {
			success: false,
			error: {
				code: "UNAUTHORIZED",
				message: "Bearer token required",
				details: {
					"www-authenticate": `Bearer resource_metadata="${resourceMetadataUrl}"`,
				},
			},
		};
	}

	return validateAccessToken(ctx, token, options);
}

/** Quote an RFC 7235 auth-param value. */
function quoteParam(value: string): string {
	return `"${value
		.replace(/\\/g, "\\\\")
		.replace(/"/g, '\\"')
		.replace(/[\r\n]+/g, " ")}"`;
}

/** RFC 6750 `error` value for each failure code that concerns a presented token. */
const OAUTH_ERROR_BY_CODE: Partial<Record<string, string>> = {
	INVALID_TOKEN: "invalid_token",
	TOKEN_EXPIRED: "invalid_token",
	INVALID_AUDIENCE: "invalid_token",
	INVALID_ISSUER: "invalid_token",
	DELEGATION_REVOKED: "invalid_token",
	DPOP_REQUIRED: "invalid_token",
};

/**
 * Build a 401 Unauthorized response for MCP clients.
 * `WWW-Authenticate` follows RFC 6750 and the MCP authorization spec: `Bearer [error="invalid_token", error_description="..."], resource_metadata="<RFC 9728 URL>"[, scope="..."]`. A request with no credentials carries no `error` (RFC 6750 section 3.1). The body is a JSON-RPC error (code -32001) whose `data.code` is the machine readable reason.
 */
export function buildUnauthorizedResponse(
	ctx: McpAuthContext,
	error: { code: string; message: string },
	options: { scope?: string[]; resourceMetadataUrl?: string } = {},
): Response {
	const resourceMetadataUrl =
		options.resourceMetadataUrl ?? `${ctx.config.baseUrl}/.well-known/oauth-protected-resource`;
	const oauthError = OAUTH_ERROR_BY_CODE[error.code];

	const params: string[] = [];
	if (oauthError) {
		params.push(`error="${oauthError}"`, `error_description=${quoteParam(error.message)}`);
	}
	params.push(`resource_metadata=${quoteParam(resourceMetadataUrl)}`);
	if (options.scope && options.scope.length > 0) {
		params.push(`scope=${quoteParam(options.scope.join(" "))}`);
	}
	const wwwAuthenticate = `Bearer ${params.join(", ")}`;

	return new Response(
		JSON.stringify({
			jsonrpc: "2.0",
			error: {
				code: -32001,
				message: error.message,
				data: { code: error.code },
			},
			id: null,
		}),
		{
			status: 401,
			headers: {
				"Content-Type": "application/json",
				"Cache-Control": "no-store",
				"WWW-Authenticate": wwwAuthenticate,
				"Access-Control-Expose-Headers": "WWW-Authenticate",
			},
		},
	);
}
