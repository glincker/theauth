import type { McpAuthContext, McpClient, Result } from "./types.js";
import { hashClientSecret, verifyClientSecret } from "./utils.js";

/**
 * Check a client's credentials for a token or revocation request.
 *
 * Public clients pass without a secret. Confidential clients must present a
 * secret that matches the stored digest (constant-time compare). A legacy
 * plaintext row is accepted once and upgraded to a digest when the store
 * implements `updateClientSecret`.
 */
export async function authenticateClient(
	ctx: McpAuthContext,
	client: McpClient,
	presentedSecret: string | null,
): Promise<Result<true>> {
	if (client.clientType !== "confidential") {
		return { success: true, data: true };
	}
	if (!presentedSecret || !client.clientSecret) {
		return {
			success: false,
			error: { code: "INVALID_CLIENT", message: "Invalid client_secret" },
		};
	}
	const check = await verifyClientSecret(presentedSecret, client.clientSecret);
	if (!check.valid) {
		return {
			success: false,
			error: { code: "INVALID_CLIENT", message: "Invalid client_secret" },
		};
	}
	if (check.needsRehash && ctx.updateClientSecret) {
		try {
			await ctx.updateClientSecret(client.clientId, await hashClientSecret(presentedSecret));
		} catch {
			// The credential check already passed; a failed upgrade is retried on
			// the next successful authentication.
		}
	}
	return { success: true, data: true };
}
