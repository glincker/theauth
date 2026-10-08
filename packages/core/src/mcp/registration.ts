import { generateId } from "../crypto/web-crypto.js";
import type { McpAuthContext, McpClient, McpClientRegistrationResponse, Result } from "./types.js";
import { McpClientRegistrationSchema } from "./types.js";
import { generateSecureToken, hashClientSecret } from "./utils.js";

/**
 * Dynamic Client Registration (RFC 7591).
 *
 * Endpoint logic for: POST /mcp/register
 *
 * Validates the registration request, generates client credentials (the
 * secret is stored as a SHA-256 digest),
 * persists the client via the context store, and returns the
 * RFC 7591-compliant registration response.
 */
export async function registerClient(
	ctx: McpAuthContext,
	body: unknown,
): Promise<Result<McpClientRegistrationResponse>> {
	// ── Validate input ──────────────────────────────────────────────────
	const parsed = McpClientRegistrationSchema.safeParse(body);
	if (!parsed.success) {
		return {
			success: false,
			error: {
				code: "INVALID_CLIENT_METADATA",
				message: "Invalid client registration request",
				details: { issues: parsed.error.flatten().fieldErrors },
			},
		};
	}

	const data = parsed.data;
	const redirectUris = data.redirect_uris;
	const grantTypes = data.grant_types ?? ["authorization_code"];
	const responseTypes = data.response_types ?? ["code"];
	const authMethod = data.token_endpoint_auth_method ?? "client_secret_basic";

	// ── Validate redirect_uris are required for authorization_code ────
	if (grantTypes.includes("authorization_code") && redirectUris.length === 0) {
		return {
			success: false,
			error: {
				code: "INVALID_REDIRECT_URI",
				message: "redirect_uris are required when grant_types includes authorization_code",
			},
		};
	}

	// ── Validate grant_type / response_type consistency ──────────────
	if (grantTypes.includes("authorization_code") && !responseTypes.includes("code")) {
		return {
			success: false,
			error: {
				code: "INVALID_CLIENT_METADATA",
				message:
					"response_types must include 'code' when grant_types includes 'authorization_code'",
			},
		};
	}

	// ── Validate redirect URIs ──────────────────────────────────────
	for (const uri of redirectUris) {
		try {
			const parsed = new URL(uri);
			// Localhost is allowed for development; production requires HTTPS
			if (
				parsed.protocol !== "https:" &&
				parsed.hostname !== "localhost" &&
				parsed.hostname !== "127.0.0.1" &&
				parsed.hostname !== "[::1]"
			) {
				return {
					success: false,
					error: {
						code: "INVALID_REDIRECT_URI",
						message: `redirect_uri must use HTTPS (or localhost for development): ${uri}`,
					},
				};
			}
			// Fragment not allowed per OAuth 2.1
			if (parsed.hash) {
				return {
					success: false,
					error: {
						code: "INVALID_REDIRECT_URI",
						message: `redirect_uri must not contain a fragment: ${uri}`,
					},
				};
			}
		} catch {
			return {
				success: false,
				error: {
					code: "INVALID_REDIRECT_URI",
					message: `redirect_uri is not a valid URL: ${uri}`,
				},
			};
		}
	}

	// ── Generate credentials ────────────────────────────────────────
	const clientId = generateId();
	const isPublic = authMethod === "none";
	const clientSecret = isPublic ? null : generateSecureToken(48);

	// ── Persist ─────────────────────────────────────────────────────
	const now = new Date();
	const client: McpClient = {
		clientId,
		// Only the digest is stored; the raw secret is returned once below.
		clientSecret: clientSecret === null ? null : await hashClientSecret(clientSecret),
		clientName: data.client_name ?? null,
		clientUri: data.client_uri ?? null,
		logoUri: data.logo_uri ?? null,
		redirectUris,
		grantTypes,
		responseTypes,
		tokenEndpointAuthMethod: authMethod,
		scope: data.scope ?? null,
		contacts: data.contacts ?? null,
		tosUri: data.tos_uri ?? null,
		policyUri: data.policy_uri ?? null,
		softwareId: data.software_id ?? null,
		softwareVersion: data.software_version ?? null,
		clientType: isPublic ? "public" : "confidential",
		disabled: false,
		userId: null,
		createdAt: now,
		updatedAt: now,
	};

	await ctx.storeClient(client);

	// ── Build response ──────────────────────────────────────────────
	const response: McpClientRegistrationResponse = {
		client_id: clientId,
		client_id_issued_at: Math.floor(now.getTime() / 1000),
		redirect_uris: redirectUris,
		token_endpoint_auth_method: authMethod,
		grant_types: grantTypes,
		response_types: responseTypes,
		...(data.client_name ? { client_name: data.client_name } : {}),
		...(data.client_uri ? { client_uri: data.client_uri } : {}),
		...(data.logo_uri ? { logo_uri: data.logo_uri } : {}),
		...(data.scope ? { scope: data.scope } : {}),
		...(data.contacts ? { contacts: data.contacts } : {}),
		...(data.tos_uri ? { tos_uri: data.tos_uri } : {}),
		...(data.policy_uri ? { policy_uri: data.policy_uri } : {}),
		...(data.software_id ? { software_id: data.software_id } : {}),
		...(data.software_version ? { software_version: data.software_version } : {}),
		...(clientSecret !== null ? { client_secret: clientSecret, client_secret_expires_at: 0 } : {}),
	};

	return { success: true, data: response };
}
