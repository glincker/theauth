import type { ConfirmationOutcome } from "../agent/confirmation-http.js";
import type { TrustedProxyConfig } from "../auth/client-ip.js";
import { dpopAlgsOf } from "../mcp/dpop.js";
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
	"confirmation_required",
	"confirmation_failed",
	"device_not_found",
	"device_revoked",
	"device_expired",
]);

/** HTTP status for a denial code: 401 for identity failures, 403 for everything else. */
export function statusForDecisionCode(code: DecisionCode): 401 | 403 {
	return UNAUTHENTICATED_CODES.has(code) ? 401 : 403;
}

function deny(code: DecisionCode, message: string, challenge = "Bearer"): RequireAgentResult {
	const status = statusForDecisionCode(code);
	const response = errorResponse(
		code,
		message,
		status,
		status === 401 ? { "WWW-Authenticate": challenge } : undefined,
	);
	return { ok: false, status, code, message, response };
}

/** The `WWW-Authenticate` value for a bound token that was refused: a DPoP challenge when DPoP is on (RFC 9449 section 7.1), else Bearer. */
export function confirmationChallenge(auth: TheAuth, message: string): string {
	const dpop = auth.agentConfirmation?.config.dpop;
	if (!dpop) return "Bearer";
	const algs = dpopAlgsOf(dpop).join(" ");
	return `DPoP error="invalid_token", error_description="${message.replace(/["\\\r\n]/g, " ")}", algs="${algs}"`;
}

/** Pull the bearer token out of an Authorization header (scheme is case-insensitive). */
export function bearerTokenOf(request: Request): string {
	const header = request.headers.get("authorization") ?? "";
	const match = /^Bearer\s+(.+)$/i.exec(header);
	return match?.[1]?.trim() ?? "";
}

/** The agent token and the scheme it came with. `DPoP` is the scheme of a sender constrained token (RFC 9449 section 7.1). */
export function agentCredentialOf(
	request: Request,
): { token: string; scheme: "Bearer" | "DPoP" } | null {
	const header = request.headers.get("authorization") ?? "";
	const match = /^(Bearer|DPoP)\s+(.+)$/i.exec(header);
	const token = match?.[2]?.trim();
	if (!match || !token) return null;
	return { token, scheme: match[1]?.toLowerCase() === "dpop" ? "DPoP" : "Bearer" };
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
	const credential = agentCredentialOf(request);
	if (!credential) return deny("invalid_token", "Missing or invalid Authorization header");
	const { token } = credential;

	// Proofs of possession (DPoP, certificate thumbprint) are checked before the token is looked up.
	// A hand built TheAuth (a test double) may lack the verifier: then nothing is proven and bound tokens fail closed.
	const proved: ConfirmationOutcome = auth.agentConfirmation
		? await auth.agentConfirmation.verify(request, token, credential.scheme)
		: { ok: true, confirmation: undefined };
	if (!proved.ok) {
		return {
			ok: false,
			status: 401,
			code: "confirmation_failed",
			message: "Proof of possession refused",
			response: proved.response,
		};
	}

	const result = await auth.authorizeByToken(
		token,
		{ action: options.action, resource: options.resource },
		{
			ip: options.clientIp
				? options.clientIp(request)
				: (resolveRequestIp(request, options.trustedProxy) ?? undefined),
			userAgent: request.headers.get("user-agent") ?? undefined,
			...(proved.confirmation && { confirmation: proved.confirmation }),
		},
	);
	if (!result.allowed) {
		// A missing code only comes from hand-built results; treat it as a plain denial.
		const code = result.code ?? "no_permission";
		const message = result.reason ?? "Authorization denied";
		const bound = code === "confirmation_required" || code === "confirmation_failed";
		return deny(code, message, bound ? confirmationChallenge(auth, message) : undefined);
	}

	const agent = await auth.agent.validateToken(token);
	if (!agent) return deny("invalid_token", "Invalid or expired agent token");
	const { token: _token, ...identity } = agent;
	return { ok: true, agent: identity, auditId: result.auditId };
}
