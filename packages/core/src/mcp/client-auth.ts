import type { McpAuthContext, McpClient, Result } from "./types.js";
import { hashClientSecret, verifyClientSecret } from "./utils.js";

/**
 * Check a client's credentials for a token or revocation request.
 * Confidential clients must present a secret that matches the stored digest (constant-time compare). A legacy plaintext row is accepted once and upgraded to a digest when the store implements `updateClientSecret`. A client registered for `private_key_jwt` authenticates only through a verified assertion (`assertionVerified`); a secret never works for it, and an assertion never works for a client with another method.
 */
export async function authenticateClient(
	ctx: McpAuthContext,
	client: McpClient,
	presentedSecret: string | null,
	assertionVerified = false,
): Promise<Result<true>> {
	const usesAssertion = client.tokenEndpointAuthMethod === "private_key_jwt";
	if (usesAssertion || assertionVerified) {
		if (usesAssertion && assertionVerified) return { success: true, data: true };
		return {
			success: false,
			error: {
				code: "INVALID_CLIENT",
				message: usesAssertion
					? "private_key_jwt client authentication is required"
					: "Client is not registered for private_key_jwt",
			},
		};
	}
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
