import { checkFreshness } from "./freshness.js";
import type { McpAuthContext, Result } from "./types.js";

export interface GrantLivenessInput {
	/** jti of the access token the grant descends from. Use a random id for a fresh grant. */
	jti: string;
	sub: string;
	clientId: string;
	/** When the authority was granted (code or refresh token creation), not now: watermarks compare against it. */
	grantedAt: Date;
	/** Agent the client is bound to, if any. */
	agentId?: string | undefined;
}

/**
 * Revocation check for a grant at the token endpoint. Always LIVE, whatever freshness mode resource servers run: the endpoint is the choke point, so a revoked grant must not mint anything. Reads the jti, sub, client, agent and binding rows through the same helper resource servers use, and fails closed. A hit is `{ revoked: true }`, a store error is a `SERVER_ERROR` result.
 */
export async function checkGrantLive(
	ctx: McpAuthContext,
	input: GrantLivenessInput,
): Promise<Result<{ revoked: boolean }>> {
	const outcome = await checkFreshness(
		ctx,
		{
			jti: input.jti,
			sub: input.sub,
			clientId: input.clientId,
			// Same second as a revoke counts as revoked (fail closed), matching the store.
			iat: Math.floor(input.grantedAt.getTime() / 1000),
			exp: Math.floor(Date.now() / 1000) + 60,
			...(input.agentId ? { agentId: input.agentId } : {}),
		},
		"live",
	);
	if (outcome.ok) return { success: true, data: { revoked: false } };
	if (outcome.kind === "unavailable") {
		return {
			success: false,
			error: { code: "SERVER_ERROR", message: "Revocation status is temporarily unavailable" },
		};
	}
	return { success: true, data: { revoked: true } };
}
