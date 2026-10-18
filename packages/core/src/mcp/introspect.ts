import { authenticateEndpointClient, checkEndpointRateLimit } from "./endpoint-client-auth.js";
import { verifyAccessJwt } from "./keys.js";
import type {
	McpInactiveReason,
	McpIntrospectionResponse,
	McpRevocationDetails,
} from "./revocation-types.js";
import { MCP_REVOCATION_DEFAULTS } from "./revocation-types.js";
import type { McpActorClaim, McpAuthContext, McpTokenPayload, Result } from "./types.js";
import { parseRequestBody } from "./utils.js";
import { validateAccessToken } from "./validate.js";

/** The one response a caller gets for anything it is not entitled to know about. */
function bare(): McpIntrospectionResponse {
	return { active: false };
}

/** What an introspection leaves behind for an audit log. Never the token or a hash of it. */
export interface McpIntrospectionAuditEvent {
	callerClientId: string;
	/** Only set once the signature verified. */
	jti?: string;
	active: boolean;
	reason?: McpInactiveReason;
	entitled: boolean;
}

export interface McpIntrospectionHooks {
	/** Called after every decision for an authenticated caller. Errors are swallowed. */
	audit?: (event: McpIntrospectionAuditEvent) => void | Promise<void>;
}

function envInt(name: string): number | undefined {
	const proc = (globalThis as { process?: { env?: Record<string, string | undefined> } }).process;
	const n = Number(proc?.env?.[name]);
	return Number.isFinite(n) && n >= 1 ? Math.floor(n) : undefined;
}

function audiencesOf(aud: unknown): string[] {
	if (typeof aud === "string") return [aud];
	if (Array.isArray(aud)) return aud.filter((a): a is string => typeof a === "string");
	return [];
}

/**
 * The caller is entitled when it is the token's own client, or a configured resource server whose
 * audiences include one of the token's audiences. Returns the audience to validate against.
 */
function entitlement(
	ctx: McpAuthContext,
	callerClientId: string,
	payload: { client_id?: unknown; aud?: unknown },
): { entitled: boolean; audience: string | undefined } {
	const audiences = audiencesOf(payload.aud);
	const rs = ctx.config.introspection?.resourceServers?.find((r) => r.clientId === callerClientId);
	const shared = rs ? audiences.find((a) => rs.audiences.includes(a)) : undefined;
	const own = payload.client_id === callerClientId;
	return { entitled: own || shared !== undefined, audience: shared ?? audiences[0] };
}

function reasonOf(error: { code: string; details?: Record<string, unknown> }): McpInactiveReason {
	const revocation = error.details?.revocation as McpRevocationDetails | undefined;
	if (revocation && typeof revocation.reason === "string") return revocation.reason;
	if (error.code === "TOKEN_EXPIRED") return "expired";
	if (error.details?.delegation) return "delegation_revoked";
	return "invalid";
}

async function report(
	hooks: McpIntrospectionHooks | undefined,
	event: McpIntrospectionAuditEvent,
): Promise<void> {
	try {
		await hooks?.audit?.(event);
	} catch {
		// Auditing never changes the answer.
	}
}

/**
 * RFC 7662 for one token and one authenticated caller. The signature and claims are verified first (no store is read for a token that does not verify), then the live freshness check runs, always, whatever the configured mode. Only a caller entitled to the token learns anything: `active: true` with the claims, or `active: false` with the reason. Everyone else, and every token that cannot be verified, gets exactly `{ "active": false }`. Both outcomes run the same crypto and the same live check, so response time does not separate "revoked" from "never issued to you". A store failure is an error (503 at the HTTP layer), never `active: false`, so a resource server does not mistake an outage for a revocation.
 */
export async function introspectToken(
	ctx: McpAuthContext,
	token: string,
	callerClientId: string,
	hooks?: McpIntrospectionHooks,
): Promise<Result<McpIntrospectionResponse>> {
	const inactive = async (
		entitled: boolean,
		reason: McpInactiveReason | undefined,
		jti?: string,
	): Promise<Result<McpIntrospectionResponse>> => {
		await report(hooks, {
			callerClientId,
			active: false,
			entitled,
			...(entitled && reason ? { reason } : {}),
			...(jti ? { jti } : {}),
		});
		return {
			success: true,
			data: entitled && reason ? { active: false, theauth_inactive_reason: reason } : bare(),
		};
	};

	if (token.length > MCP_REVOCATION_DEFAULTS.introspectionMaxTokenLength) {
		return inactive(false, undefined);
	}

	let payload: McpTokenPayload;
	try {
		payload = (await verifyAccessJwt(ctx, token)) as unknown as McpTokenPayload;
	} catch (err) {
		// jose attaches the claims to an expiry error only after the signature verified.
		const code = (err as { code?: unknown }).code;
		const claims = (err as { payload?: unknown }).payload;
		if (code === "ERR_JWT_EXPIRED" && typeof claims === "object" && claims !== null) {
			const c = claims as { client_id?: unknown; aud?: unknown; jti?: unknown };
			const { entitled } = entitlement(ctx, callerClientId, c);
			return inactive(entitled, "expired", typeof c.jti === "string" ? c.jti : undefined);
		}
		return inactive(false, undefined);
	}

	const { entitled, audience } = entitlement(ctx, callerClientId, payload);
	if (!audience || typeof payload.jti !== "string") return inactive(entitled, "invalid");

	const cnfJkt = typeof payload.cnf?.jkt === "string" ? payload.cnf.jkt : null;
	const validated = await validateAccessToken(ctx, token, {
		expectedAudience: audience,
		freshness: "live",
		presentedDpopJkt: cnfJkt,
	});
	if (!validated.success) {
		if (validated.error.code === "SERVER_ERROR") {
			return {
				success: false,
				error: { code: "SERVER_ERROR", message: "Token status is temporarily unavailable" },
			};
		}
		return inactive(entitled, reasonOf(validated.error), payload.jti);
	}
	if (!entitled) return inactive(false, undefined, payload.jti);

	const session = validated.data;
	const act: McpActorClaim | undefined =
		typeof payload.act === "object" && payload.act !== null ? payload.act : undefined;
	await report(hooks, { callerClientId, active: true, entitled: true, jti: payload.jti });
	return {
		success: true,
		data: {
			active: true,
			...(payload.scope ? { scope: payload.scope } : {}),
			client_id: payload.client_id,
			sub: payload.sub,
			exp: payload.exp,
			...(typeof payload.iat === "number" ? { iat: payload.iat } : {}),
			aud: Array.isArray(payload.aud) ? payload.aud : audience,
			iss: payload.iss,
			jti: payload.jti,
			token_type: cnfJkt ? "DPoP" : "Bearer",
			...(cnfJkt ? { cnf: { jkt: cnfJkt } } : {}),
			...(act ? { act } : {}),
			...(session.agent ? { agent_id: session.agent.id } : {}),
			...(session.binding ? { theauth_dlg: session.binding } : {}),
		},
	};
}

/**
 * `POST /mcp/introspect` (RFC 7662). Order: parse the form, authenticate the client (public clients refused, nothing about the token is read before this), rate limit per client, then introspect. Errors are `INVALID_CLIENT` (401), `INVALID_REQUEST` (400), `RATE_LIMITED` (429, `details.retryAfter`) and `SERVER_ERROR` (503).
 */
export async function handleIntrospection(
	ctx: McpAuthContext,
	request: Request,
	hooks?: McpIntrospectionHooks,
): Promise<Result<McpIntrospectionResponse>> {
	let body: Record<string, string>;
	try {
		body = await parseRequestBody(request);
	} catch {
		return {
			success: false,
			error: { code: "INVALID_REQUEST", message: "Malformed request body" },
		};
	}

	const authenticated = await authenticateEndpointClient(
		ctx,
		request,
		body,
		`${ctx.config.baseUrl}/mcp/introspect`,
	);
	if (!authenticated.success) return authenticated;
	const clientId = authenticated.data.clientId;

	const limit =
		ctx.config.introspection?.maxRequestsPerMinute ??
		envInt("THEAUTH_MCP_INTROSPECT_RPM") ??
		MCP_REVOCATION_DEFAULTS.introspectionMaxRequestsPerMinute;
	const wait = await checkEndpointRateLimit(ctx, "introspect", clientId, limit);
	if (wait !== null) {
		return {
			success: false,
			error: {
				code: "RATE_LIMITED",
				message: "Too many introspection requests",
				details: { retryAfter: wait },
			},
		};
	}

	const token = body.token;
	if (!token) {
		return { success: false, error: { code: "INVALID_REQUEST", message: "token is required" } };
	}
	// Only access tokens are introspectable. A refresh token is opaque to resource servers.
	if (body.token_type_hint === "refresh_token") {
		await report(hooks, { callerClientId: clientId, active: false, entitled: false });
		return { success: true, data: bare() };
	}
	return introspectToken(ctx, token, clientId, hooks);
}
