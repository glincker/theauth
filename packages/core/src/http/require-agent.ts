import type { TrustedProxyConfig } from "../auth/client-ip.js";
import type { DecisionCode } from "../permission/codes.js";
import type { TheAuth } from "../theauth-core.js";
import type { AgentIdentity } from "../types.js";
import { resolveRequestIp } from "./node.js";
import { errorResponse } from "./respond.js";

export interface RequireAgentOptions {
	/** Action the agent must be allowed to perform, for example "read". */
	action: string;
	/** Resource the action applies to, for example "invoices". */
	resource: string;
	/** Client IP resolver, used for ipAllowlist constraints and audit rows. */
	clientIp?: (request: Request) => string | undefined;
	/** Trusted proxy rules for the default resolver (used when `clientIp` is not given). Without it the socket peer address recorded by `toWebRequest` is used. */
	trustedProxy?: TrustedProxyConfig;
}

export type RequireAgentResult =
	| { ok: true; agent: Omit<AgentIdentity, "token">; auditId: string }
	| { ok: false; status: 401 | 403; code: DecisionCode; message: string; response: Response };

/** Decision codes that mean "we could not identify a usable agent" (401). Every other denial is 403. */
const UNAUTHENTICATED_CODES: ReadonlySet<DecisionCode> = new Set<DecisionCode>([
	"invalid_token",
	"agent_not_found",
	"agent_revoked",
	"agent_expired",
]);

/** HTTP status for a denial code: 401 for identity failures, 403 for everything else. */
export function statusForDecisionCode(code: DecisionCode): 401 | 403 {
	return UNAUTHENTICATED_CODES.has(code) ? 401 : 403;
}

function deny(code: DecisionCode, message: string): RequireAgentResult {
	const status = statusForDecisionCode(code);
	const response = errorResponse(
		code,
		message,
		status,
		status === 401 ? { "WWW-Authenticate": "Bearer" } : undefined,
	);
	return { ok: false, status, code, message, response };
}

/** Pull the bearer token out of an Authorization header (scheme is case-insensitive). */
export function bearerTokenOf(request: Request): string {
	const header = request.headers.get("authorization") ?? "";
	const match = /^Bearer\s+(.+)$/i.exec(header);
	return match?.[1]?.trim() ?? "";
}

/**
 * Authenticate an agent bearer token and check it may perform `action` on `resource`.
 * Returns the agent on success. On failure it returns a ready `response` with body
 * `{ error: { code, message } }`, where `code` is the decision code (never a reason string):
 * `invalid_token`, `agent_not_found`, `agent_revoked`, `agent_expired` give 401, all others 403.
 * Infrastructure errors are thrown so the framework can answer 500.
 */
export async function requireAgent(
	auth: TheAuth,
	request: Request,
	options: RequireAgentOptions,
): Promise<RequireAgentResult> {
	const token = bearerTokenOf(request);
	if (!token) return deny("invalid_token", "Missing or invalid Authorization header");

	const result = await auth.authorizeByToken(
		token,
		{ action: options.action, resource: options.resource },
		{
			ip: options.clientIp
				? options.clientIp(request)
				: (resolveRequestIp(request, options.trustedProxy) ?? undefined),
			userAgent: request.headers.get("user-agent") ?? undefined,
		},
	);
	if (!result.allowed) {
		// A missing code only comes from hand-built results; treat it as a plain denial.
		return deny(result.code ?? "no_permission", result.reason ?? "Authorization denied");
	}

	const agent = await auth.agent.validateToken(token);
	if (!agent) return deny("invalid_token", "Invalid or expired agent token");
	const { token: _token, ...identity } = agent;
	return { ok: true, agent: identity, auditId: result.auditId };
}
