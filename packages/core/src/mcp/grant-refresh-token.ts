import type { GrantClientAuth } from "./grant-common.js";
import { resolveAuthenticatedClient } from "./grant-common.js";
import { checkGrantLive } from "./grant-liveness.js";
import { canonicalizeResource, supportedScopes } from "./lenient.js";
import { revokeFamilyAndTokens, revokeStoredAccessToken } from "./revocation.js";
import { issueAccessTokenJwt, issueRefreshToken } from "./token-issue.js";
import type {
	McpAccessToken,
	McpAuthContext,
	McpTokenRequestParsed,
	McpTokenResponse,
	Result,
} from "./types.js";
import { hashToken } from "./utils.js";

/** refresh_token grant: rotate tokens. */
export async function handleRefreshTokenGrant(
	ctx: McpAuthContext,
	data: Extract<McpTokenRequestParsed, { grant_type: "refresh_token" }>,
	auth: GrantClientAuth,
	presentedJkt: string | null,
): Promise<Result<McpTokenResponse>> {
	// Look up and authenticate the client
	const resolved = await resolveAuthenticatedClient(ctx, data.client_id, auth);
	if (!resolved.success) return resolved;

	// Find the stored token (hash first, legacy plaintext second) ─
	const presented = data.refresh_token;
	const presentedHash = await hashToken(presented);
	const existingToken =
		(await ctx.findTokenByRefreshToken(presentedHash)) ??
		(await ctx.findTokenByRefreshToken(presented));

	// Bind to the client before anything is consumed, so a different client
	// cannot burn a victim's token.
	if (existingToken && existingToken.clientId !== data.client_id) {
		return {
			success: false,
			error: { code: "INVALID_GRANT", message: "client_id does not match refresh token" },
		};
	}

	// DPoP binding (RFC 9449 section 5): a bound grant only refreshes ─
	// with a proof from the same key. Checked before rotation so a thief
	// without the key cannot burn the legitimate client's token.
	if (existingToken?.dpopJkt && existingToken.dpopJkt !== presentedJkt) {
		return {
			success: false,
			error: {
				code: "INVALID_DPOP_PROOF",
				message: "Refresh token is bound to a different DPoP key",
			},
		};
	}
	const dpopJkt = existingToken?.dpopJkt ?? presentedJkt;

	// Revocation check, always LIVE: the token endpoint is the choke point, whatever freshness mode
	// resource servers run. Fails closed on a store error. Runs before rotation so a revoked grant
	// is never rotated, and the family is killed so it cannot be retried.
	if (existingToken) {
		const live = await checkGrantLive(ctx, {
			jti: existingToken.jti ?? existingToken.accessToken,
			sub: existingToken.userId,
			clientId: data.client_id,
			// A refresh token minted before a sub or client watermark is dead; one minted after is fine.
			grantedAt: existingToken.createdAt,
			agentId: resolved.data.agentId ?? undefined,
		});
		if (!live.success) return live;
		if (live.data.revoked) {
			if (existingToken.familyId) {
				await revokeFamilyAndTokens(ctx, existingToken.familyId, null).catch(() => undefined);
			}
			return {
				success: false,
				error: { code: "INVALID_GRANT", message: "The grant has been revoked" },
			};
		}
	}

	// Rotation and reuse detection (RFC 9700 section 4.14)
	const families = ctx.tokenFamilies;
	let familyId = existingToken?.familyId;
	if (families) {
		const consumed = await families.consumeToken(presented);
		if (consumed.status === "reuse" || consumed.status === "revoked") {
			// A rotated token came back: assume theft and kill the whole family.
			if (consumed.family) {
				await revokeFamilyAndTokens(ctx, consumed.family.id, existingToken);
			}
			return {
				success: false,
				error: {
					code: "INVALID_GRANT",
					message:
						consumed.status === "reuse"
							? "Refresh token reuse detected; the grant has been revoked"
							: "Refresh token family has been revoked",
				},
			};
		}
		if (consumed.status === "expired") {
			return {
				success: false,
				error: { code: "INVALID_GRANT", message: "Refresh token has expired" },
			};
		}
		if (consumed.status === "ok") {
			familyId = consumed.family?.id ?? familyId;
		}
		// "not_found": a token minted before families existed. It is accepted once
		// below and moved into a family so the next rotation is protected.
	}

	if (!existingToken) {
		return {
			success: false,
			error: { code: "INVALID_GRANT", message: "Invalid refresh token" },
		};
	}

	const refreshExpiry = new Date(
		existingToken.createdAt.getTime() + ctx.config.refreshTokenTtl * 1000,
	);
	if (refreshExpiry < new Date()) {
		return {
			success: false,
			error: { code: "INVALID_GRANT", message: "Refresh token has expired" },
		};
	}

	// Scopes: may be narrowed, never widened or unknown
	let scopes = existingToken.scope;
	if (data.scope) {
		let requested = data.scope.split(" ").filter(Boolean);
		if (ctx.config.lenientClients?.dropUnknownScopes === true && requested.length > 0) {
			const supported = supportedScopes(ctx);
			requested = requested.filter((s) => supported.has(s));
			if (requested.length === 0) {
				return {
					success: false,
					error: { code: "INVALID_SCOPE", message: "None of the requested scopes are supported" },
				};
			}
		}
		const unauthorized = requested.filter((s) => !existingToken.scope.includes(s));
		if (unauthorized.length > 0) {
			return {
				success: false,
				error: {
					code: "INVALID_SCOPE",
					message: `Scope not granted by the original authorization: ${unauthorized.join(" ")}`,
				},
			};
		}
		if (requested.length > 0) {
			scopes = requested;
		}
	}

	// Resource: equal to (or a subset of) the original grant
	// A grant is bound to one resource, so the only valid subset is that
	// resource itself. Omitting the parameter keeps the original binding.
	const originalResource = existingToken.resource;
	if (
		data.resource !== undefined &&
		canonicalizeResource(ctx, data.resource) !== (originalResource ?? ctx.config.issuer)
	) {
		return {
			success: false,
			error: {
				code: "INVALID_TARGET",
				message: "resource must match the resource of the original grant",
			},
		};
	}
	const resource = originalResource;

	// Mint first: a refused mint (agent revoked or expired) must not also revoke the old token
	// state half way. The refresh token is already rotated, and that refusal is permanent.
	const { jwt, jti, expiresAt, ttlSeconds } = await issueAccessTokenJwt(
		ctx,
		existingToken.userId,
		data.client_id,
		scopes,
		resource,
		dpopJkt,
		existingToken.auth ? { auth: existingToken.auth } : {},
	);

	// Revoke the old access token
	await revokeStoredAccessToken(ctx, existingToken);

	const rotated = await issueRefreshToken(ctx, existingToken.userId, familyId);
	const newRefreshToken = rotated.rawToken;

	const tokenRecord: McpAccessToken = {
		accessToken: await hashToken(jwt),
		refreshToken: await hashToken(newRefreshToken),
		jti,
		...(rotated.familyId ? { familyId: rotated.familyId } : {}),
		tokenType: dpopJkt ? "DPoP" : "Bearer",
		...(dpopJkt ? { dpopJkt } : {}),
		...(existingToken.auth ? { auth: existingToken.auth } : {}),
		expiresIn: ttlSeconds,
		scope: scopes,
		clientId: data.client_id,
		userId: existingToken.userId,
		resource,
		expiresAt,
		createdAt: new Date(),
	};

	await ctx.storeToken(tokenRecord);

	const response: McpTokenResponse = {
		access_token: jwt,
		token_type: dpopJkt ? "DPoP" : "Bearer",
		expires_in: ttlSeconds,
		refresh_token: newRefreshToken,
		scope: scopes.join(" "),
	};

	return { success: true, data: response };
}
