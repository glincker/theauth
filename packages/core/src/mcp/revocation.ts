import { authenticateEndpointClient } from "./endpoint-client-auth.js";
import { invalidateFreshnessCache } from "./freshness.js";
import { verifyAccessJwt } from "./keys.js";
import { revocationRowExpiry } from "./revocation-bus.js";
import type { McpRevocationStore } from "./revocation-types.js";
import type { McpAccessToken, McpAuthContext, Result } from "./types.js";
import { hashToken, parseRequestBody } from "./utils.js";

function isRevocationStore(value: unknown): value is McpRevocationStore {
	return (
		typeof value === "object" &&
		value !== null &&
		typeof (value as Record<string, unknown>).revokeMany === "function"
	);
}

/**
 * Revoke one stored access token: tell the store and, when a jti denylist is configured, deny the jti until the token would have expired on its own. Without a denylist the JWT stays cryptographically valid until `exp`; see the docs for what that means for resource servers.
 */
export async function revokeStoredAccessToken(
	ctx: McpAuthContext,
	record: Pick<McpAccessToken, "accessToken" | "jti" | "expiresAt">,
): Promise<void> {
	await ctx.revokeToken(record.accessToken);
	const denylist = ctx.config.jtiDenylist;
	if (denylist && record.jti) {
		if (isRevocationStore(denylist)) {
			// Shared denylist: every instance sharing the database refuses this jti on its next check.
			await denylist.revokeMany([
				{
					kind: "jti",
					id: record.jti,
					expiresAt: revocationRowExpiry(record.expiresAt, new Date()),
					reason: "oauth.revoke",
				},
			]);
		} else {
			await denylist.revoke(record.jti, record.expiresAt);
		}
		// Cached mode on this instance must not keep serving a positive verdict.
		invalidateFreshnessCache(ctx);
	}
}

/** Revoke a whole refresh token family and the access token tied to `record`, if known. */
export async function revokeFamilyAndTokens(
	ctx: McpAuthContext,
	familyId: string,
	record: McpAccessToken | null,
): Promise<void> {
	await ctx.tokenFamilies?.revokeFamily(familyId);
	await ctx.revokeTokenFamily?.(familyId);
	if (record) await revokeStoredAccessToken(ctx, record);
}

/** Seconds a client should wait before retrying a revoke the store could not record. */
const REVOKE_RETRY_AFTER_SECONDS = 5;

/** The store could not record a revoke. The token is still treated as revoked locally: the freshness cache drops its positive verdicts, so this instance never keeps serving the token from cache. */
function revokeUnavailable(ctx: McpAuthContext): Result<Record<string, never>> {
	invalidateFreshnessCache(ctx);
	return {
		success: false,
		error: {
			code: "SERVER_ERROR",
			message: "Revocation could not be recorded, retry shortly",
			details: { retryAfter: REVOKE_RETRY_AFTER_SECONDS },
		},
	};
}

/**
 * RFC 7009 token revocation.
 * The caller must authenticate as a client and can only revoke tokens issued to that client. A store failure while recording the revoke is a `SERVER_ERROR` with `details.retryAfter` (503 over HTTP). Unknown or foreign tokens still return success (the RFC forbids revealing whether a token exists), they just are not touched. An assertion must be addressed to the revocation endpoint (`<baseUrl>/mcp/revoke`) or the issuer, and each `jti` is accepted once across the token, revocation and introspection endpoints.
 */
export async function handleRevocation(
	ctx: McpAuthContext,
	request: Request,
): Promise<Result<Record<string, never>>> {
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
		`${ctx.config.baseUrl}/mcp/revoke`,
		{ allowPublicClients: true },
	);
	if (!authenticated.success) return authenticated;
	const clientId = authenticated.data.clientId;

	const token = body.token;
	if (!token) {
		return { success: false, error: { code: "INVALID_REQUEST", message: "token is required" } };
	}

	const ok: Result<Record<string, never>> = { success: true, data: {} };
	const hint = body.token_type_hint;

	if (hint !== "access_token") {
		const hash = await hashToken(token);
		const record =
			(await ctx.findTokenByRefreshToken(hash)) ?? (await ctx.findTokenByRefreshToken(token));
		if (record) {
			if (record.clientId !== clientId) return ok; // not this client's token
			try {
				if (record.familyId) {
					await revokeFamilyAndTokens(ctx, record.familyId, record);
				} else {
					await revokeStoredAccessToken(ctx, record);
				}
			} catch {
				return revokeUnavailable(ctx);
			}
			return ok;
		}
		if (hint === "refresh_token") return ok;
	}

	// Treat the value as an access token JWT. Only tokens we signed count.
	let verified: { jti: string; exp: Date } | null = null;
	try {
		const payload = await verifyAccessJwt(ctx, token);
		if (payload.client_id === clientId && typeof payload.jti === "string") {
			verified = {
				jti: payload.jti,
				exp: typeof payload.exp === "number" ? new Date(payload.exp * 1000) : new Date(),
			};
		}
	} catch {
		// Invalid or expired token: nothing to revoke.
	}
	if (verified) {
		try {
			await revokeStoredAccessToken(ctx, {
				accessToken: await hashToken(token),
				jti: verified.jti,
				expiresAt: verified.exp,
			});
		} catch {
			return revokeUnavailable(ctx);
		}
	}
	return ok;
}
