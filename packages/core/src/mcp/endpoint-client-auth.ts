import { verifyClientAssertion } from "./client-assertion.js";
import { authenticateClient } from "./client-auth.js";
import { resolveClient } from "./client-metadata.js";
import { getAssertionStorage } from "./jwks-fetch.js";
import type { McpAuthContext, McpClient, Result } from "./types.js";
import { extractBasicAuth } from "./utils.js";

/**
 * Client authentication shared by the revocation and introspection endpoints: `client_secret_basic`, `client_secret_post` and `private_key_jwt` (through the same assertion verifier the token endpoint uses). Exactly one method may be used per request. Every failure is `INVALID_CLIENT` with a fixed message, so the response never says which part of the credential was wrong.
 */
export interface EndpointClientAuthOptions {
	/** Accept clients that registered without a secret (`none`). Revocation does, introspection never does. */
	allowPublicClients?: boolean;
}

function invalidClient(message = "Client authentication failed"): Result<never> {
	return { success: false, error: { code: "INVALID_CLIENT", message } };
}

export async function authenticateEndpointClient(
	ctx: McpAuthContext,
	request: Request,
	body: Record<string, string>,
	endpointUrl: string,
	options: EndpointClientAuthOptions = {},
): Promise<Result<McpClient>> {
	const basic = extractBasicAuth(request);
	let assertedClientId: string | undefined;
	let assertionVerified = false;

	if (body.client_assertion !== undefined) {
		if (basic !== null || body.client_secret !== undefined) {
			return {
				success: false,
				error: {
					code: "INVALID_REQUEST",
					message: "Only one client authentication method may be used",
				},
			};
		}
		const verified = await verifyClientAssertion(ctx, {
			assertion: body.client_assertion,
			assertionType: body.client_assertion_type,
			...(body.client_id !== undefined ? { expectedClientId: body.client_id } : {}),
			tokenEndpointUrl: endpointUrl,
		});
		if (!verified.success) return verified;
		assertedClientId = verified.data.clientId;
		assertionVerified = true;
	} else if (basic !== null && body.client_secret !== undefined) {
		return {
			success: false,
			error: {
				code: "INVALID_REQUEST",
				message: "Only one client authentication method may be used",
			},
		};
	}

	if (basic !== null && body.client_id !== undefined && body.client_id !== basic[0]) {
		return invalidClient();
	}
	const clientId = assertedClientId ?? basic?.[0] ?? body.client_id;
	const secret = basic?.[1] ?? body.client_secret ?? null;
	if (!clientId) return invalidClient("client_id is required");

	const client = await resolveClient(ctx, clientId);
	if (!client || client.disabled) return invalidClient();
	if (!options.allowPublicClients && !assertionVerified && client.clientType !== "confidential") {
		return invalidClient();
	}
	const auth = await authenticateClient(ctx, client, secret, assertionVerified);
	if (!auth.success) return auth;
	return { success: true, data: client };
}

const RATE_WINDOW_SECONDS = 60;

/**
 * Fixed window request counter per client, per instance (memory unless `config.assertionStorage` is shared). Returns the seconds to wait when over `limit`, or null when the call may proceed.
 */
export async function checkEndpointRateLimit(
	ctx: McpAuthContext,
	endpoint: string,
	clientId: string,
	limit: number,
): Promise<number | null> {
	const window = Math.floor(Date.now() / 1000 / RATE_WINDOW_SECONDS);
	const { count } = await getAssertionStorage(ctx).incr(
		`mcp:ratelimit:${endpoint}:${clientId}:${window}`,
		RATE_WINDOW_SECONDS * 2,
	);
	if (count <= limit) return null;
	return RATE_WINDOW_SECONDS - (Math.floor(Date.now() / 1000) % RATE_WINDOW_SECONDS);
}
