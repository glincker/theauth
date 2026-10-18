import { eq } from "drizzle-orm";
import type { JWK } from "jose";
import { generateId } from "../crypto/web-crypto.js";
import type { Database } from "../db/database.js";
import { agents, oauthClients } from "../db/schema.js";
import { isUniqueViolation } from "../db/unique-violation.js";
import type { McpClient } from "./types.js";

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

export interface McpClientStore {
	storeClient: (client: McpClient) => Promise<void>;
	findClient: (clientId: string) => Promise<McpClient | null>;
	updateClientSecret: (clientId: string, hashedSecret: string) => Promise<void>;
	setClientAgent: (clientId: string, agentId: string | null) => Promise<void>;
}

/** OAuth clients in `theauth_oauth_clients`. Storing an existing client id updates it, so pre registered clients can be stored on every boot. */
export function createDbClientStore(db: Database): McpClientStore {
	async function update(c: McpClient): Promise<void> {
		await db
			.update(oauthClients)
			.set({
				...valuesFromClient(c),
				// undefined leaves a binding made through `setClientAgent` alone.
				...(c.agentId !== undefined ? { agentId: c.agentId } : {}),
			})
			.where(eq(oauthClients.clientId, c.clientId));
	}

	return {
		async storeClient(client) {
			if (client.agentId) await assertAgentExists(db, client.agentId);
			const existing = await db
				.select({ id: oauthClients.id })
				.from(oauthClients)
				.where(eq(oauthClients.clientId, client.clientId));
			if (existing.length > 0) return update(client);
			try {
				await db.insert(oauthClients).values({
					id: generateId(),
					clientId: client.clientId,
					...valuesFromClient(client),
					agentId: client.agentId ?? null,
					createdAt: client.createdAt,
				});
			} catch (error) {
				// A concurrent boot stored the same pre registered client first.
				if (!isUniqueViolation(error)) throw error;
				await update(client);
			}
		},

		async findClient(clientId) {
			const rows = await db.select().from(oauthClients).where(eq(oauthClients.clientId, clientId));
			return rows[0] ? clientFromRow(rows[0]) : null;
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
				.select({ id: oauthClients.id })
				.from(oauthClients)
				.where(eq(oauthClients.clientId, clientId));
			if (rows.length === 0) throw new Error(`Unknown client: ${clientId}`);
			await db
				.update(oauthClients)
				.set({ agentId, updatedAt: new Date() })
				.where(eq(oauthClients.clientId, clientId));
		},
	};
}
