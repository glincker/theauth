import { and, count, eq, inArray, isNull, lt, notInArray } from "drizzle-orm";
import type { JWK } from "jose";
import { generateId } from "../crypto/web-crypto.js";
import type { Database } from "../db/database.js";
import { agents, oauthAccessTokens, oauthAuthorizationCodes, oauthClients } from "../db/schema.js";
import { toStoreConflict } from "../db/store-conflict.js";
import type { McpClient } from "./types.js";

const toSec = (d: Date): number => Math.floor(d.getTime() / 1000);

type ClientRow = typeof oauthClients.$inferSelect;

/** Fields McpClient has but the table has no column for. They live in the `metadata` JSON column. */
interface ClientExtras {
	contacts?: string[] | null;
	tosUri?: string | null;
	policyUri?: string | null;
	softwareId?: string | null;
	softwareVersion?: string | null;
}

function readExtras(metadata: Record<string, unknown> | null): ClientExtras {
	if (!metadata) return {};
	const str = (v: unknown): string | null => (typeof v === "string" ? v : null);
	return {
		contacts:
			Array.isArray(metadata.contacts) && metadata.contacts.every((c) => typeof c === "string")
				? (metadata.contacts as string[])
				: null,
		tosUri: str(metadata.tosUri),
		policyUri: str(metadata.policyUri),
		softwareId: str(metadata.softwareId),
		softwareVersion: str(metadata.softwareVersion),
	};
}

function clientFromRow(row: ClientRow): McpClient {
	const extras = readExtras(row.metadata);
	return {
		clientId: row.clientId,
		clientSecret: row.clientSecret,
		clientName: row.clientName,
		clientUri: row.clientUri,
		logoUri: row.logoUri,
		redirectUris: row.redirectUris,
		grantTypes: row.grantTypes,
		responseTypes: row.responseTypes,
		tokenEndpointAuthMethod: row.tokenEndpointAuthMethod,
		scope: row.scope,
		contacts: extras.contacts ?? null,
		tosUri: extras.tosUri ?? null,
		policyUri: extras.policyUri ?? null,
		softwareId: extras.softwareId ?? null,
		softwareVersion: extras.softwareVersion ?? null,
		clientType: row.type,
		disabled: row.disabled,
		userId: row.userId,
		agentId: row.agentId,
		...(row.source === "cimd" ? { source: "cimd" as const } : {}),
		...(row.jwks ? { jwks: row.jwks as unknown as { keys: JWK[] } } : {}),
		...(row.jwksUri ? { jwksUri: row.jwksUri } : {}),
		...(row.disabledReason ? { disabledReason: row.disabledReason } : {}),
		...(row.cimdDocument && row.cimdDigest && row.cimdFetchedAt != null && row.cimdExpiresAt != null
			? {
					cimd: {
						digest: row.cimdDigest,
						fetchedAt: new Date(row.cimdFetchedAt * 1000),
						expiresAt: new Date(row.cimdExpiresAt * 1000),
						document: row.cimdDocument,
					},
				}
			: {}),
		createdAt: row.createdAt,
		updatedAt: row.updatedAt,
	};
}

function valuesFromClient(c: McpClient) {
	const metadata: Record<string, unknown> = {};
	if (c.contacts) metadata.contacts = c.contacts;
	if (c.tosUri) metadata.tosUri = c.tosUri;
	if (c.policyUri) metadata.policyUri = c.policyUri;
	if (c.softwareId) metadata.softwareId = c.softwareId;
	if (c.softwareVersion) metadata.softwareVersion = c.softwareVersion;
	return {
		clientSecret: c.clientSecret,
		clientName: c.clientName,
		clientUri: c.clientUri,
		logoUri: c.logoUri,
		redirectUris: c.redirectUris,
		grantTypes: c.grantTypes,
		responseTypes: c.responseTypes,
		tokenEndpointAuthMethod: c.tokenEndpointAuthMethod,
		type: c.clientType,
		disabled: c.disabled,
		disabledReason: c.disabledReason ?? null,
		cimdDocument: c.cimd?.document ?? null,
		cimdDigest: c.cimd?.digest ?? null,
		cimdFetchedAt: c.cimd ? toSec(c.cimd.fetchedAt) : null,
		cimdExpiresAt: c.cimd ? toSec(c.cimd.expiresAt) : null,
		scope: c.scope,
		userId: c.userId,
		source: c.source ?? null,
		jwks: (c.jwks as { keys: Record<string, unknown>[] } | undefined) ?? null,
		jwksUri: c.jwksUri ?? null,
		metadata: Object.keys(metadata).length > 0 ? metadata : null,
		updatedAt: c.updatedAt,
	};
}

/** Throws a readable error when `agentId` is not an agent row (or the agents table does not exist). */
async function assertAgentExists(db: Database, agentId: string): Promise<void> {
	let found: boolean;
	try {
		const rows = await db.select({ id: agents.id }).from(agents).where(eq(agents.id, agentId));
		found = rows.length > 0;
	} catch (error) {
		throw new Error(
			"Binding an OAuth client to an agent needs the agent tables. Enable `agents` in createTheAuth.",
			{ cause: error },
		);
	}
	if (!found) throw new Error(`Cannot bind the client: agent "${agentId}" does not exist`);
}

export interface McpStoreClientOptions {
	/** A cache refresh from a fetched document: `disabled`, `disabledReason` and `agentId` of an existing row are never overwritten, so an admin's decision survives. */
	preserveAdminState?: boolean;
}

export interface McpClientStore {
	storeClient: (client: McpClient, options?: McpStoreClientOptions) => Promise<void>;
	findClient: (clientId: string) => Promise<McpClient | null>;
	updateClientSecret: (clientId: string, hashedSecret: string) => Promise<void>;
	setClientAgent: (clientId: string, agentId: string | null) => Promise<void>;
	/** Admin disable or enable. Enabling clears the reason. Throws for an unknown client. */
	setClientDisabled: (clientId: string, disabled: boolean, reason?: string | null) => Promise<void>;
	/** Deletes every stored token row of the client (refresh tokens die with them) and returns the jtis, so a denylist can refuse the access tokens until they expire. */
	revokeClientTokens: (
		clientId: string,
	) => Promise<{ jtis: Array<{ jti: string; expiresAt: Date }> }>;
	/** Every stored Client ID Metadata Document client_id. */
	listCimdClientIds: () => Promise<string[]>;
	/** CIMD clients nobody ever consented to: no token rows, no agent binding, not disabled. */
	countUnconsentedCimdClients?: () => Promise<number>;
	/** Deletes unconsented CIMD clients last updated before `before`. Returns the number removed. */
	deleteStaleUnconsentedCimdClients?: (before: Date) => Promise<number>;
}

/** Collations such as MySQL's default compare client ids case insensitively; only an exact match is the same client. */
function exact<T extends { clientId: string }>(rows: T[], clientId: string): T | undefined {
	return rows.find((r) => r.clientId === clientId);
}

/** OAuth clients in `theauth_oauth_clients`. Storing an existing client id updates it, so pre registered clients can be stored on every boot. */
export function createDbClientStore(db: Database): McpClientStore {
	async function update(c: McpClient, options: McpStoreClientOptions): Promise<void> {
		const values = valuesFromClient(c);
		const { disabled: _d, disabledReason: _r, ...rest } = values;
		await db
			.update(oauthClients)
			.set({
				...(options.preserveAdminState ? rest : values),
				// undefined leaves a binding made through `setClientAgent` alone.
				...(!options.preserveAdminState && c.agentId !== undefined ? { agentId: c.agentId } : {}),
			})
			.where(eq(oauthClients.clientId, c.clientId));
	}

	return {
		async storeClient(client, options = {}) {
			if (client.agentId) await assertAgentExists(db, client.agentId);
			const matches = await db
				.select({ id: oauthClients.id, clientId: oauthClients.clientId })
				.from(oauthClients)
				.where(eq(oauthClients.clientId, client.clientId));
			if (matches.length > 0) {
				if (!exact(matches, client.clientId)) {
					throw new Error("client_id collides with another client under this collation");
				}
				return update(client, options);
			}
			try {
				await db.insert(oauthClients).values({
					id: generateId(),
					clientId: client.clientId,
					...valuesFromClient(client),
					agentId: client.agentId ?? null,
					createdAt: client.createdAt,
				});
			} catch (error) {
				// A concurrent boot stored the same client first.
				if (!toStoreConflict(error, "oauth_clients")) throw error;
				const raced = await db
					.select({ id: oauthClients.id, clientId: oauthClients.clientId })
					.from(oauthClients)
					.where(eq(oauthClients.clientId, client.clientId));
				if (!exact(raced, client.clientId)) {
					throw new Error("client_id collides with another client under this collation");
				}
				await update(client, options);
			}
		},
		async findClient(clientId) {
			const rows = await db.select().from(oauthClients).where(eq(oauthClients.clientId, clientId));
			const row = exact(rows, clientId);
			return row ? clientFromRow(row) : null;
		},

		async updateClientSecret(clientId, hashedSecret) {
			await db
				.update(oauthClients)
				.set({ clientSecret: hashedSecret, updatedAt: new Date() })
				.where(eq(oauthClients.clientId, clientId));
		},

		async setClientAgent(clientId, agentId) {
			if (agentId !== null) await assertAgentExists(db, agentId);
			const rows = await db
				.select({ id: oauthClients.id, clientId: oauthClients.clientId })
				.from(oauthClients)
				.where(eq(oauthClients.clientId, clientId));
			if (!exact(rows, clientId)) throw new Error(`Unknown client: ${clientId}`);
			await db
				.update(oauthClients)
				.set({ agentId, updatedAt: new Date() })
				.where(eq(oauthClients.clientId, clientId));
		},

		async setClientDisabled(clientId, disabled, reason) {
			const rows = await db
				.select({ id: oauthClients.id, clientId: oauthClients.clientId })
				.from(oauthClients)
				.where(eq(oauthClients.clientId, clientId));
			if (!exact(rows, clientId)) throw new Error(`Unknown client: ${clientId}`);
			await db
				.update(oauthClients)
				.set({
					disabled,
					disabledReason: disabled ? (reason ?? null) : null,
					updatedAt: new Date(),
				})
				.where(eq(oauthClients.clientId, clientId));
		},

		async revokeClientTokens(clientId) {
			const matched = await db
				.select({
					id: oauthAccessTokens.id,
					clientId: oauthAccessTokens.clientId,
					jti: oauthAccessTokens.jti,
					expiresAt: oauthAccessTokens.accessTokenExpiresAt,
				})
				.from(oauthAccessTokens)
				.where(eq(oauthAccessTokens.clientId, clientId));
			const rows = matched.filter((r) => r.clientId === clientId);
			if (rows.length > 0) {
				await db.delete(oauthAccessTokens).where(
					inArray(
						oauthAccessTokens.id,
						rows.map((r) => r.id),
					),
				);
			}
			const jtis: Array<{ jti: string; expiresAt: Date }> = [];
			for (const r of rows) if (r.jti) jtis.push({ jti: r.jti, expiresAt: r.expiresAt });
			return { jtis };
		},

		async listCimdClientIds() {
			const rows = await db
				.select({ clientId: oauthClients.clientId })
				.from(oauthClients)
				.where(eq(oauthClients.source, "cimd"));
			return rows.map((r) => r.clientId);
		},

		async countUnconsentedCimdClients() {
			const rows = await db.select({ n: count() }).from(oauthClients).where(unconsentedCimd());
			return Number(rows[0]?.n ?? 0);
		},

		async deleteStaleUnconsentedCimdClients(before) {
			const where = and(unconsentedCimd(), lt(oauthClients.updatedAt, before));
			const rows = await db.select({ n: count() }).from(oauthClients).where(where);
			await db.delete(oauthClients).where(where);
			return Number(rows[0]?.n ?? 0);
		},
	};

	/** CIMD rows with no token rows, no pending authorization code, no agent binding, not disabled by an admin. */
	function unconsentedCimd() {
		return and(
			eq(oauthClients.source, "cimd"),
			isNull(oauthClients.agentId),
			eq(oauthClients.disabled, false),
			notInArray(
				oauthClients.clientId,
				db.select({ c: oauthAccessTokens.clientId }).from(oauthAccessTokens),
			),
			notInArray(
				oauthClients.clientId,
				db.select({ c: oauthAuthorizationCodes.clientId }).from(oauthAuthorizationCodes),
			),
		);
	}
}
