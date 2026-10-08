import { authenticateClient } from "./client-auth.js";
import { resolveClient } from "./client-metadata.js";
import { verifyAccessJwt } from "./keys.js";
import type { McpAccessToken, McpAuthContext, Result } from "./types.js";
import { extractBasicAuth, hashToken, parseRequestBody } from "./utils.js";

/**
 * Revoke one stored access token: tell the store and, when a jti denylist is
 * configured, deny the jti until the token would have expired on its own.
 * Without a denylist the JWT stays cryptographically valid until `exp`; see
 * the docs for what that means for resource servers.
 */
export async function revokeStoredAccessToken(
	ctx: McpAuthContext,
	record: Pick<McpAccessToken, "accessToken" | "jti" | "expiresAt">,
): Promise<void> {
	await ctx.revokeToken(record.accessToken);
	if (ctx.config.jtiDenylist && record.jti) {
		await ctx.config.jtiDenylist.revoke(record.jti, record.expiresAt);
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

/**
 * RFC 7009 token revocation.
 *
 * POST /mcp/revoke
 *
 * The caller must authenticate as a client and can only revoke tokens issued
 * to that client. Unknown or foreign tokens still return success (the RFC
 * forbids revealing whether a token exists), they just are not touched.
 */
export async function handleRevocation(
	ctx: McpAuthContext,
	request: Request,
): Promise<Result<Record<string, never>>> {
	const body = await parseRequestBody(request);
	const basic = extractBasicAuth(request);
	const clientId = basic?.[0] ?? body.client_id;
	const secret = basic?.[1] ?? body.client_secret ?? null;
	const token = body.token;

	if (!clientId) {
		return { success: false, error: { code: "INVALID_CLIENT", message: "client_id is required" } };
	}
	if (!token) {
		return { success: false, error: { code: "INVALID_REQUEST", message: "token is required" } };
	}

	const client = await resolveClient(ctx, clientId);
	if (!client || client.disabled) {
		return { success: false, error: { code: "INVALID_CLIENT", message: "Unknown client" } };
	}
	const auth = await authenticateClient(ctx, client, secret);
	if (!auth.success) return auth;

	const ok: Result<Record<string, never>> = { success: true, data: {} };
	const hint = body.token_type_hint;

	if (hint !== "access_token") {
		const hash = await hashToken(token);
		const record =
			(await ctx.findTokenByRefreshToken(hash)) ?? (await ctx.findTokenByRefreshToken(token));
		if (record) {
			if (record.clientId !== clientId) return ok; // not this client's token
			if (record.familyId) {
				await revokeFamilyAndTokens(ctx, record.familyId, record);
			} else {
				await revokeStoredAccessToken(ctx, record);
			}
			return ok;
		}
		if (hint === "refresh_token") return ok;
	}

	// Treat the value as an access token JWT. Only tokens we signed count.
	try {
		const payload = await verifyAccessJwt(ctx, token);
		if (payload.client_id !== clientId || typeof payload.jti !== "string") return ok;
		const exp = typeof payload.exp === "number" ? new Date(payload.exp * 1000) : new Date();
		await revokeStoredAccessToken(ctx, {
			accessToken: await hashToken(token),
			jti: payload.jti,
			expiresAt: exp,
		});
	} catch {
		// Invalid or expired token: nothing to revoke.
	}
	return ok;
}
