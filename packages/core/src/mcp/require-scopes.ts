import type { McpUserAuthRequirement } from "./step-up.js";
import {
	buildInsufficientUserAuthResponse,
	buildStepUpResponse,
	checkUserAuthentication,
} from "./step-up.js";
import type {
	McpAuthContext,
	McpAuthErrorCode,
	McpRejectedToken,
	RequireScopesResult,
} from "./types.js";
import { extractBearerToken } from "./utils.js";
import { buildUnauthorizedResponse, validateAccessToken } from "./validate.js";

export type { McpAuthErrorCode, McpRejectedToken, RequireScopesResult } from "./types.js";

const KNOWN_CODES: ReadonlySet<string> = new Set<McpAuthErrorCode>([
	"UNAUTHORIZED",
	"INVALID_TOKEN",
	"TOKEN_EXPIRED",
	"INVALID_AUDIENCE",
	"INVALID_ISSUER",
	"DELEGATION_REVOKED",
	"INSUFFICIENT_SCOPE",
	"DPOP_REQUIRED",
	"INSUFFICIENT_USER_AUTHENTICATION",
	"SERVER_ERROR",
]);

const DELEGATION_REASONS: ReadonlySet<string> = new Set([
	"delegation_revoked",
	"delegation_expired",
	"agent_revoked",
	"agent_expired",
]);

/** True when the freshness check (`details.revocation`) says the token's delegation or agent is gone. */
function isDelegationReason(details: Record<string, unknown> | undefined): boolean {
	const r = details?.revocation;
	if (typeof r !== "object" || r === null) return false;
	const reason = (r as { reason?: unknown }).reason;
	return typeof reason === "string" && DELEGATION_REASONS.has(reason);
}

/** Refine the validator's code with what its details say (delegation and DPoP failures share INVALID_TOKEN there). */
function refineCode(code: string, details: Record<string, unknown> | undefined): McpAuthErrorCode {
	if (details?.delegation) return "DELEGATION_REVOKED";
	if (isDelegationReason(details)) return "DELEGATION_REVOKED";
	if (details?.dpopMissing === true) return "DPOP_REQUIRED";
	return KNOWN_CODES.has(code) ? (code as McpAuthErrorCode) : "INVALID_TOKEN";
}

function readRejected(details: Record<string, unknown> | undefined): McpRejectedToken | undefined {
	const r = details?.rejected;
	return typeof r === "object" && r !== null ? (r as McpRejectedToken) : undefined;
}

/**
 * Validates the Bearer token on a request and asserts that it carries all `requiredScopes`.
 *
 * On failure the result says why, in a form code can branch on and an audit log can record:
 * `status` (401 for a missing or bad token, 403 for missing scopes, 500 for a server misconfiguration), `error.code` (see {@link McpAuthErrorCode}), and `rejected` (who the token belonged to, only when its signature verified). `response` is the ready-made HTTP answer with the `WWW-Authenticate` challenge (RFC 6750, RFC 9728 `resource_metadata`, and `scope`).
 *
 * @example
 * ```typescript
 * const check = await requireScopes(ctx, request, ['mcp:write']);
 * if (!check.authorized) {
 *   if (check.rejected) await audit.denied(check.rejected.agentId, check.error.code);
 *   return check.response;
 * }
 * // check.session is available here
 * ```
 */
export async function requireScopes(
	ctx: McpAuthContext,
	request: Request,
	requiredScopes: string[],
	/** Also demand a login of this strength or age (RFC 9470). A shortfall gives 401 `insufficient_user_authentication`. */
	userAuth?: McpUserAuthRequirement,
): Promise<RequireScopesResult> {
	const token = extractBearerToken(request);

	if (!token) {
		const error = { code: "UNAUTHORIZED" as const, message: "Bearer token required" };
		return {
			authorized: false,
			status: 401,
			error,
			response: buildUnauthorizedResponse(ctx, error, { scope: requiredScopes }),
		};
	}

	// Validate without scope enforcement first, so a bad token (401) stays distinct from a
	// valid token with the wrong scopes (403).
	const tokenResult = await validateAccessToken(ctx, token, {
		expectedAudience: ctx.config.resource,
	});

	if (!tokenResult.success) {
		const details = tokenResult.error.details;
		const code = refineCode(tokenResult.error.code, details);
		const error = { code, message: tokenResult.error.message };
		if (code === "SERVER_ERROR") {
			return {
				authorized: false,
				status: 500,
				error,
				response: new Response(
					JSON.stringify({ error: "server_error", error_description: error.message }),
					{
						status: 500,
						headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
					},
				),
			};
		}
		const rejected = readRejected(details);
		return {
			authorized: false,
			status: 401,
			error,
			...(rejected ? { rejected } : {}),
			response: buildUnauthorizedResponse(ctx, error, { scope: requiredScopes }),
		};
	}

	const session = tokenResult.data;
	const missing = requiredScopes.filter((s) => !session.scopes.includes(s));
	if (missing.length > 0) {
		return {
			authorized: false,
			status: 403,
			error: {
				code: "INSUFFICIENT_SCOPE",
				message: `Token is missing required scope: ${missing.join(" ")}`,
			},
			rejected: {
				clientId: session.clientId,
				subject: session.userId,
				tokenId: session.tokenId,
				...(session.agent ? { agentId: session.agent.id } : {}),
			},
			response: buildStepUpResponse(ctx, {
				currentScopes: session.scopes,
				requiredScopes,
				resource: session.resource ?? undefined,
			}),
		};
	}

	const tooWeak = checkUserAuthentication(session.auth, userAuth);
	if (tooWeak) {
		return {
			authorized: false,
			status: 401,
			error: {
				code: "INSUFFICIENT_USER_AUTHENTICATION",
				message:
					tooWeak.reason === "max_age"
						? "A more recent authentication is required"
						: "A stronger authentication is required",
			},
			rejected: {
				clientId: session.clientId,
				subject: session.userId,
				tokenId: session.tokenId,
				...(session.agent ? { agentId: session.agent.id } : {}),
			},
			response: buildInsufficientUserAuthResponse(ctx, tooWeak),
		};
	}

	return { authorized: true, session };
}
