import { eq } from "drizzle-orm";
import { generateId } from "../crypto/web-crypto.js";
import { oidcClients } from "../db/schema.js";
import type { Result } from "../mcp/types.js";
import {
	CLIENT_ID_BYTE_LENGTH,
	CLIENT_SECRET_BYTE_LENGTH,
	generateRandomHex,
	hashSecret,
	makeError,
	registerClientSchema,
} from "./oidc-provider-helpers.js";
import type {
	OidcClient,
	OidcProviderContext,
	RegisterClientInput,
} from "./oidc-provider-types.js";

/** OIDC client registration, lookup and deletion. */
export function createOidcClients(ctx: OidcProviderContext) {
	const { db, supportedScopes, logout } = ctx;

	async function registerClient(input: RegisterClientInput): Promise<Result<OidcClient>> {
		const parsed = registerClientSchema.safeParse(input);
		if (!parsed.success) {
			return {
				success: false,
				error: makeError("INVALID_INPUT", parsed.error.errors[0]?.message ?? "Invalid input", {
					issues: parsed.error.errors,
				}),
			};
		}

		const {
			clientName,
			redirectUris,
			grantTypes = ["authorization_code", "refresh_token"],
			responseTypes = ["code"],
			scopes = supportedScopes,
			tokenEndpointAuthMethod = "client_secret_post",
			postLogoutRedirectUris,
			backchannelLogoutUri,
		} = parsed.data;

		if ((postLogoutRedirectUris || backchannelLogoutUri) && !logout) {
			return {
				success: false,
				error: makeError(
					"LOGOUT_NOT_ENABLED",
					"postLogoutRedirectUris and backchannelLogoutUri need config.logout",
				),
			};
		}

		const clientId = generateRandomHex(CLIENT_ID_BYTE_LENGTH);
		const rawSecret = generateRandomHex(CLIENT_SECRET_BYTE_LENGTH);
		const secretHash = await hashSecret(rawSecret);
		const now = new Date();

		try {
			await db.insert(oidcClients).values({
				id: generateId(),
				clientId,
				clientSecretHash: secretHash,
				clientName,
				redirectUris,
				grantTypes,
				responseTypes,
				scopes,
				tokenEndpointAuthMethod,
				createdAt: now,
				updatedAt: now,
			});

			if (logout && (postLogoutRedirectUris || backchannelLogoutUri)) {
				try {
					await logout.setClientLogoutConfig(clientId, {
						postLogoutRedirectUris: postLogoutRedirectUris ?? [],
						backchannelLogoutUri: backchannelLogoutUri ?? null,
					});
				} catch (err) {
					await db.delete(oidcClients).where(eq(oidcClients.clientId, clientId));
					return {
						success: false,
						error: makeError(
							"INVALID_INPUT",
							err instanceof Error ? err.message : "Invalid logout configuration",
						),
					};
				}
			}

			return {
				success: true,
				data: {
					clientId,
					clientSecret: rawSecret,
					clientName,
					redirectUris,
					grantTypes,
					responseTypes,
					scopes,
					tokenEndpointAuthMethod,
					createdAt: now,
				},
			};
		} catch (err) {
			return {
				success: false,
				error: makeError(
					"CLIENT_REGISTRATION_FAILED",
					err instanceof Error ? err.message : "Failed to register client",
				),
			};
		}
	}

	async function getClient(clientId: string): Promise<Result<OidcClient>> {
		if (!clientId || clientId.trim() === "") {
			return { success: false, error: makeError("INVALID_INPUT", "clientId must not be empty") };
		}

		const rows = await db.select().from(oidcClients).where(eq(oidcClients.clientId, clientId));

		const row = rows[0];
		if (!row) {
			return { success: false, error: makeError("CLIENT_NOT_FOUND", "Client not found") };
		}

		return {
			success: true,
			data: {
				clientId: row.clientId,
				clientSecret: null, // Never return the hashed secret
				clientName: row.clientName,
				redirectUris: row.redirectUris,
				grantTypes: row.grantTypes,
				responseTypes: row.responseTypes,
				scopes: row.scopes,
				tokenEndpointAuthMethod: row.tokenEndpointAuthMethod,
				createdAt: row.createdAt,
			},
		};
	}

	async function deleteClient(clientId: string): Promise<Result<void>> {
		if (!clientId || clientId.trim() === "") {
			return { success: false, error: makeError("INVALID_INPUT", "clientId must not be empty") };
		}

		const rows = await db
			.select({ id: oidcClients.id })
			.from(oidcClients)
			.where(eq(oidcClients.clientId, clientId));

		if (rows.length === 0) {
			return { success: false, error: makeError("CLIENT_NOT_FOUND", "Client not found") };
		}

		try {
			await db.delete(oidcClients).where(eq(oidcClients.clientId, clientId));
			if (logout) await logout.deleteClientLogoutConfig(clientId);
			return { success: true, data: undefined };
		} catch (err) {
			return {
				success: false,
				error: makeError(
					"CLIENT_DELETE_FAILED",
					err instanceof Error ? err.message : "Failed to delete client",
				),
			};
		}
	}

	return {
		registerClient,
		getClient,
		deleteClient,
	};
}
