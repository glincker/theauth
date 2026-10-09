import { getDpopAlgs, readDpopHeader, verifyDpopProof } from "./dpop.js";
import type { McpAuthContext, McpDelegationHop, McpSession } from "./types.js";
import { validateAccessToken } from "./validate.js";

/** Who is calling, as established by a verified access token. */
export interface McpPrincipal {
	/** Subject of the token (the user the agent acts for). */
	userId: string;
	/** OAuth client that obtained the token. */
	clientId: string;
	/** Agent identity from `agent_id`, `agent_type` and `trust_tier` claims, or null. */
	agent: { id: string; type?: string; trustTier?: string } | null;
	/** RFC 8693 `act` chain, current actor first. Empty when there is none. */
	delegationChain: McpDelegationHop[];
	scopes: string[];
	resource: string | null;
	tokenId: string;
	expiresAt: Date;
	/** Which Authorization scheme the caller used. */
	scheme: "Bearer" | "DPoP";
	/** Thumbprint of the proof key when the token is DPoP-bound, else null. */
	dpopJkt: string | null;
	/** The underlying session, for code that already works with `McpSession`. */
	session: McpSession;
}

export type McpProtectedHandler = (
	request: Request,
	principal: McpPrincipal,
) => Response | Promise<Response>;

export interface RequireMcpAuthOptions {
	/** Scopes the token must carry. A shortfall gives 403 `insufficient_scope`. */
	requiredScopes?: string[];
	/** Canonical URI of this resource server. Default: `McpConfig.resource`. */
	expectedAudience?: string;
	/**
	 * The URL clients sign as the proof `htu`. Set it behind a proxy or when the
	 * public URL differs from `request.url`. Default: `request.url`.
	 */
	resourceUrl?: string;
	/** RFC 9728 metadata URL for challenges. Default: `<baseUrl>/.well-known/oauth-protected-resource`. */
	resourceMetadataUrl?: string;
	/** Refuse tokens that are not DPoP-bound. Default: `McpConfig.dpop.required`. */
	requireDpop?: boolean;
	/** Demand a server nonce in resource-request proofs. Default: `McpConfig.dpop.requireNonce`. */
	requireNonce?: boolean;
}

const CORS_EXPOSE = "WWW-Authenticate, DPoP-Nonce";

function quote(value: string): string {
	return `"${value.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

function challenge(scheme: "Bearer" | "DPoP", params: Record<string, string | undefined>): string {
	const parts = Object.entries(params)
		.filter((entry): entry is [string, string] => entry[1] !== undefined)
		.map(([key, value]) => `${key}=${quote(value)}`);
	return parts.length > 0 ? `${scheme} ${parts.join(", ")}` : scheme;
}

interface FailureInit {
	status: 401 | 403 | 500;
	error: string;
	description: string;
	challenges: string[];
	extra?: Record<string, unknown>;
	nonce?: string;
}

function failure(init: FailureInit): Response {
	const headers = new Headers({
		"Content-Type": "application/json",
		"Cache-Control": "no-store",
		"Access-Control-Expose-Headers": CORS_EXPOSE,
	});
	for (const value of init.challenges) headers.append("WWW-Authenticate", value);
	if (init.nonce) headers.set("DPoP-Nonce", init.nonce);
	return new Response(
		JSON.stringify({ error: init.error, error_description: init.description, ...init.extra }),
		{ status: init.status, headers },
	);
}

function parseAuthorization(request: Request): { scheme: "Bearer" | "DPoP"; token: string } | null {
	const header = request.headers.get("authorization");
	const match = header ? /^(Bearer|DPoP)\s+([^\s,]+)$/i.exec(header.trim()) : null;
	const scheme = match?.[1]?.toLowerCase();
	const token = match?.[2];
	if (!token) return null;
	return { scheme: scheme === "dpop" ? "DPoP" : "Bearer", token };
}

/**
 * Protect a Web API handler with MCP OAuth. Accepts `Authorization: Bearer`
 * and, when `McpConfig.dpop` is set, `Authorization: DPoP` with a proof.
 *
 * What it enforces:
 * - signature, issuer, expiry and audience (RFC 8707) of the access token
 * - for DPoP: proof signature, `htm`, `htu`, `iat`, `ath`, nonce (optional),
 *   `jti` replay, and that the proof key matches the token's `cnf.jkt`
 * - bearer downgrade: a DPoP-bound token sent with the Bearer scheme is refused
 * - required scopes (403 `insufficient_scope`)
 *
 * Failures return a 401 or 403 with `WWW-Authenticate` challenges per RFC 6750,
 * RFC 9449 and RFC 9728 (`resource_metadata`). On success the handler runs with
 * the verified {@link McpPrincipal}.
 *
 * @example
 * ```ts
 * const handler = requireMcpAuth(ctx, async (req, principal) => {
 *   return Response.json({ user: principal.userId, agent: principal.agent?.id });
 * }, { requiredScopes: ["mcp:read"] });
 * ```
 */
export function requireMcpAuth(
	ctx: McpAuthContext,
	handler: McpProtectedHandler,
	options: RequireMcpAuthOptions = {},
): (request: Request) => Promise<Response> {
	const dpopConfig = ctx.config.dpop;
	const requireDpop = options.requireDpop ?? dpopConfig?.required === true;
	const metadataUrl =
		options.resourceMetadataUrl ?? `${ctx.config.baseUrl}/.well-known/oauth-protected-resource`;
	const algs = dpopConfig ? getDpopAlgs(ctx).join(" ") : undefined;

	const bearer = (extra: Record<string, string | undefined> = {}) =>
		challenge("Bearer", { ...extra, resource_metadata: metadataUrl });
	const dpop = (extra: Record<string, string | undefined> = {}) =>
		challenge("DPoP", { ...extra, algs, resource_metadata: metadataUrl });
	/** Every scheme this resource accepts, so the client can pick one. */
	const offered = (extra: Record<string, string | undefined> = {}) =>
		dpopConfig && requireDpop
			? [dpop(extra)]
			: dpopConfig
				? [bearer(extra), dpop(extra)]
				: [bearer(extra)];

	return async (request: Request): Promise<Response> => {
		const audience = options.expectedAudience ?? ctx.config.resource;
		if (!audience) {
			return failure({
				status: 500,
				error: "server_error",
				description:
					"requireMcpAuth needs expectedAudience or McpConfig.resource so tokens for other resources are rejected",
				challenges: [],
			});
		}

		const presented = parseAuthorization(request);
		if (!presented) {
			return failure({
				status: 401,
				error: "unauthorized",
				description: "Authorization required",
				challenges: offered(),
			});
		}

		// ── DPoP proof ────────────────────────────────────────────────
		let proofJkt: string | null = null;
		if (presented.scheme === "DPoP") {
			if (!dpopConfig) {
				return failure({
					status: 401,
					error: "invalid_request",
					description: "The DPoP scheme is not enabled on this resource",
					challenges: [bearer({ error: "invalid_request" })],
				});
			}
			const proof = readDpopHeader(request);
			if (!proof) {
				return failure({
					status: 401,
					error: "invalid_dpop_proof",
					description: "Exactly one DPoP proof header is required",
					challenges: [dpop({ error: "invalid_dpop_proof" })],
				});
			}
			const verified = await verifyDpopProof(ctx, {
				proof,
				method: request.method,
				url: options.resourceUrl ?? request.url,
				accessToken: presented.token,
				requireNonce: options.requireNonce ?? dpopConfig.requireNonce === true,
			});
			if (!verified.success) {
				const nonce = verified.error.details?.dpopNonce;
				if (verified.error.code === "USE_DPOP_NONCE" && typeof nonce === "string") {
					return failure({
						status: 401,
						error: "use_dpop_nonce",
						description: verified.error.message,
						challenges: [
							dpop({ error: "use_dpop_nonce", error_description: verified.error.message }),
						],
						nonce,
					});
				}
				return failure({
					status: 401,
					error: "invalid_dpop_proof",
					description: verified.error.message,
					challenges: [
						dpop({ error: "invalid_dpop_proof", error_description: verified.error.message }),
					],
				});
			}
			proofJkt = verified.data.jkt;
		}

		// ── Access token (also catches bearer use of a bound token) ───
		const result = await validateAccessToken(ctx, presented.token, {
			expectedAudience: audience,
			presentedDpopJkt: proofJkt,
		});
		if (!result.success) {
			if (result.error.code === "SERVER_ERROR") {
				return failure({
					status: 500,
					error: "server_error",
					description: result.error.message,
					challenges: [],
				});
			}
			const dpopRelated = result.error.details?.dpopBound === true || presented.scheme === "DPoP";
			const params = { error: "invalid_token", error_description: result.error.message };
			return failure({
				status: 401,
				error: "invalid_token",
				description: result.error.message,
				challenges: dpopRelated && dpopConfig ? [dpop(params)] : [bearer(params)],
			});
		}

		const session = result.data;
		if (requireDpop && !session.dpopJkt) {
			return failure({
				status: 401,
				error: "invalid_token",
				description: "This resource only accepts DPoP-bound access tokens",
				challenges: [dpop({ error: "invalid_token" })],
			});
		}

		// ── Scopes ────────────────────────────────────────────────────
		const required = options.requiredScopes ?? [];
		if (required.some((scope) => !session.scopes.includes(scope))) {
			const params = {
				error: "insufficient_scope",
				error_description: "Token lacks required scopes",
				scope: required.join(" "),
			};
			return failure({
				status: 403,
				error: "insufficient_scope",
				description: "Token lacks required scopes",
				challenges: [presented.scheme === "DPoP" ? dpop(params) : bearer(params)],
				extra: { required_scopes: required, current_scopes: session.scopes },
			});
		}

		return handler(request, {
			userId: session.userId,
			clientId: session.clientId,
			agent: session.agent ?? null,
			delegationChain: session.delegationChain ?? [],
			scopes: session.scopes,
			resource: session.resource,
			tokenId: session.tokenId,
			expiresAt: session.expiresAt,
			scheme: presented.scheme,
			dpopJkt: session.dpopJkt ?? null,
			session,
		});
	};
}
