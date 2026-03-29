import { randomUUID } from "node:crypto";
import type { Database } from "kavachos";
import { agentCards, and, eq, like } from "kavachos";

export interface AgentCapability {
	name: string;
	description: string;
	inputSchema?: Record<string, unknown>;
	outputSchema?: Record<string, unknown>;
}

export interface AgentCard {
	id: string;
	name: string;
	description: string;
	version: string;
	protocols: string[];
	capabilities: AgentCapability[];
	authRequirements: {
		type: "bearer" | "oauth2" | "api-key" | "none";
		scopes?: string[];
	};
	endpoint?: string;
	metadata?: Record<string, unknown>;
	createdAt: string;
	updatedAt: string;
}

function rowToCard(row: typeof agentCards.$inferSelect): AgentCard {
	return {
		id: row.id,
		name: row.name,
		description: row.description ?? "",
		version: row.version,
		protocols: row.protocols,
		capabilities: row.capabilities as AgentCapability[],
		authRequirements: row.authRequirements as AgentCard["authRequirements"],
		endpoint: row.endpoint ?? undefined,
		metadata: row.metadata ?? undefined,
		createdAt: row.createdAt.toISOString(),
		updatedAt: row.updatedAt.toISOString(),
	};
}

/**
 * Create the A2A discovery module for agent capability cards.
 *
 * Accepts the KavachOS database instance, which is available on the
 * `kavach.db` property returned by `createKavach()`.
 *
 * @example
 * ```typescript
 * import { createKavach } from 'kavachos';
 * import { createDiscoveryModule } from '@kavachos/plugin-discovery';
 *
 * const kavach = await createKavach({ database: { provider: 'sqlite', url: 'kavach.db' } });
 * const discovery = createDiscoveryModule(kavach.db);
 * const card = await discovery.registerCard(agentId, { name: 'Code Reviewer', ... });
 * ```
 */
export function createDiscoveryModule(db: Database) {
	async function registerCard(
		agentId: string,
		card: Omit<AgentCard, "id" | "createdAt" | "updatedAt">,
	): Promise<AgentCard> {
		const now = new Date();
		const id = randomUUID();

		await db.insert(agentCards).values({
			id,
			agentId,
			name: card.name,
			description: card.description,
			version: card.version,
			protocols: card.protocols,
			capabilities: card.capabilities,
			authRequirements: card.authRequirements,
			endpoint: card.endpoint ?? null,
			metadata: card.metadata ?? null,
			createdAt: now,
			updatedAt: now,
		});

		return {
			...card,
			id,
			createdAt: now.toISOString(),
			updatedAt: now.toISOString(),
		};
	}

	async function getCard(agentId: string): Promise<AgentCard | null> {
		const rows = await db.select().from(agentCards).where(eq(agentCards.agentId, agentId)).limit(1);

		const row = rows[0];
		if (!row) return null;
		return rowToCard(row);
	}

	async function searchCards(query: {
		protocols?: string[];
		capabilities?: string[];
		name?: string;
	}): Promise<AgentCard[]> {
		const conditions = [];

		if (query.name) {
			conditions.push(like(agentCards.name, `%${query.name}%`));
		}

		const rows =
			conditions.length > 0
				? await db
						.select()
						.from(agentCards)
						.where(and(...conditions))
				: await db.select().from(agentCards);

		let cards = rows.map(rowToCard);

		// Filter by protocol membership (JSON column — filter in application layer)
		if (query.protocols && query.protocols.length > 0) {
			const wantedProtocols = new Set(query.protocols);
			cards = cards.filter((c) => c.protocols.some((p) => wantedProtocols.has(p)));
		}

		// Filter by capability name membership
		if (query.capabilities && query.capabilities.length > 0) {
			const wantedCaps = new Set(query.capabilities);
			cards = cards.filter((c) => c.capabilities.some((cap) => wantedCaps.has(cap.name)));
		}

		return cards;
	}

	async function updateCard(agentId: string, updates: Partial<AgentCard>): Promise<AgentCard> {
		const existing = await getCard(agentId);
		if (!existing) {
			throw new Error(`No capability card found for agent "${agentId}"`);
		}

		const now = new Date();
		const updateValues: Partial<typeof agentCards.$inferInsert> = { updatedAt: now };

		if (updates.name !== undefined) updateValues.name = updates.name;
		if (updates.description !== undefined) updateValues.description = updates.description;
		if (updates.version !== undefined) updateValues.version = updates.version;
		if (updates.protocols !== undefined) updateValues.protocols = updates.protocols;
		if (updates.capabilities !== undefined) updateValues.capabilities = updates.capabilities;
		if (updates.authRequirements !== undefined)
			updateValues.authRequirements = updates.authRequirements;
		if (updates.endpoint !== undefined) updateValues.endpoint = updates.endpoint;
		if (updates.metadata !== undefined) updateValues.metadata = updates.metadata;

		await db.update(agentCards).set(updateValues).where(eq(agentCards.agentId, agentId));

		const updated = await getCard(agentId);
		// getCard will always return a value here since we just verified it exists and updated it
		return updated as AgentCard;
	}

	async function removeCard(agentId: string): Promise<void> {
		await db.delete(agentCards).where(eq(agentCards.agentId, agentId));
	}

	return {
		registerCard,
		getCard,
		searchCards,
		updateCard,
		removeCard,
	};
}

export type DiscoveryModule = ReturnType<typeof createDiscoveryModule>;
