import { createHash, randomBytes, randomUUID } from "node:crypto";
import { and, eq } from "drizzle-orm";
import type { Database } from "../db/database.js";
import { agents, permissions } from "../db/schema.js";
import type {
	AgentFilter,
	AgentIdentity,
	CreateAgentInput,
	Permission,
	UpdateAgentInput,
} from "../types.js";

interface AgentModuleConfig {
	db: Database;
	maxPerUser: number;
	defaultPermissions: string[];
	tokenExpiry: string;
}

/**
 * Generate a secure agent token.
 * Returns { token, hash, prefix } where:
 * - token: the full token (given to the agent, never stored)
 * - hash: SHA-256 hash (stored in DB)
 * - prefix: first 8 chars (for identification in logs/UI)
 */
function generateAgentToken(): { token: string; hash: string; prefix: string } {
	const tokenBytes = randomBytes(32);
	const token = `kv_${tokenBytes.toString("base64url")}`;
	const hash = createHash("sha256").update(token).digest("hex");
	const prefix = token.slice(0, 11); // "kv_" + 8 chars
	return { token, hash, prefix };
}

function parseTokenExpiry(expiry: string): Date {
	const now = Date.now();
	const match = expiry.match(/^(\d+)([smhd])$/);
	if (!match) {
		throw new Error(`Invalid token expiry format: ${expiry}. Use format like "24h", "7d", "30m".`);
	}
	const value = Number.parseInt(match[1] as string, 10);
	const unit = match[2];
	const multipliers: Record<string, number> = {
		s: 1000,
		m: 60 * 1000,
		h: 60 * 60 * 1000,
		d: 24 * 60 * 60 * 1000,
	};
	return new Date(now + value * (multipliers[unit as string] ?? 0));
}

/**
 * Create the agent identity module.
 * Handles CRUD operations for AI agent identities.
 */
export function createAgentModule(config: AgentModuleConfig) {
	const { db, maxPerUser, tokenExpiry } = config;

	async function create(input: CreateAgentInput): Promise<AgentIdentity & { token: string }> {
		// Check max agents per user
		const existing = await db
			.select()
			.from(agents)
			.where(and(eq(agents.ownerId, input.ownerId), eq(agents.status, "active")));

		if (existing.length >= maxPerUser) {
			throw new Error(
				`User ${input.ownerId} has reached the maximum of ${maxPerUser} active agents.`,
			);
		}

		const id = randomUUID();
		const { token, hash, prefix } = generateAgentToken();
		const now = new Date();
		const expires = input.expiresAt ?? parseTokenExpiry(tokenExpiry);

		// Insert agent
		await db.insert(agents).values({
			id,
			ownerId: input.ownerId,
			tenantId: input.tenantId ?? null,
			name: input.name,
			type: input.type,
			status: "active",
			tokenHash: hash,
			tokenPrefix: prefix,
			expiresAt: expires,
			metadata: input.metadata ?? {},
			createdAt: now,
			updatedAt: now,
		});

		// Insert permissions
		if (input.permissions.length > 0) {
			await db.insert(permissions).values(
				input.permissions.map((p) => ({
					id: randomUUID(),
					agentId: id,
					resource: p.resource,
					actions: p.actions,
					constraints: p.constraints ?? null,
					createdAt: now,
				})),
			);
		}

		return {
			id,
			ownerId: input.ownerId,
			tenantId: input.tenantId,
			name: input.name,
			type: input.type,
			token,
			permissions: input.permissions,
			status: "active",
			expiresAt: expires,
			createdAt: now,
			updatedAt: now,
		};
	}

	async function get(agentId: string): Promise<AgentIdentity | null> {
		const rows = await db.select().from(agents).where(eq(agents.id, agentId)).limit(1);
		const agent = rows[0];
		if (!agent) return null;

		const perms = await db.select().from(permissions).where(eq(permissions.agentId, agentId));

		return {
			id: agent.id,
			ownerId: agent.ownerId,
			tenantId: agent.tenantId ?? undefined,
			name: agent.name,
			type: agent.type as AgentIdentity["type"],
			token: "", // never return token after creation
			permissions: perms.map(toPermission),
			status: agent.status as AgentIdentity["status"],
			expiresAt: agent.expiresAt,
			createdAt: agent.createdAt,
			updatedAt: agent.updatedAt,
		};
	}

	async function list(filter?: AgentFilter): Promise<AgentIdentity[]> {
		let query = db.select().from(agents).$dynamic();

		const conditions = [];
		if (filter?.userId) conditions.push(eq(agents.ownerId, filter.userId));
		if (filter?.tenantId) conditions.push(eq(agents.tenantId, filter.tenantId));
		if (filter?.status) conditions.push(eq(agents.status, filter.status));
		if (filter?.type) conditions.push(eq(agents.type, filter.type));

		if (conditions.length > 0) {
			query = query.where(and(...conditions));
		}

		const rows = await query;

		// Load permissions for all agents
		const agentIds = rows.map((r) => r.id);
		const permsByAgent = new Map<string, Permission[]>();
		for (const id of agentIds) {
			const perms = await db.select().from(permissions).where(eq(permissions.agentId, id));
			permsByAgent.set(id, perms.map(toPermission));
		}

		return rows.map((agent) => ({
			id: agent.id,
			ownerId: agent.ownerId,
			tenantId: agent.tenantId ?? undefined,
			name: agent.name,
			type: agent.type as AgentIdentity["type"],
			token: "",
			permissions: permsByAgent.get(agent.id) ?? [],
			status: agent.status as AgentIdentity["status"],
			expiresAt: agent.expiresAt,
			createdAt: agent.createdAt,
			updatedAt: agent.updatedAt,
		}));
	}

	async function update(agentId: string, input: UpdateAgentInput): Promise<AgentIdentity> {
		const existing = await get(agentId);
		if (!existing) throw new Error(`Agent ${agentId} not found.`);

		const now = new Date();

		await db
			.update(agents)
			.set({
				name: input.name ?? existing.name,
				expiresAt: input.expiresAt ?? existing.expiresAt,
				metadata: input.metadata,
				updatedAt: now,
			})
			.where(eq(agents.id, agentId));

		// Replace permissions if provided
		if (input.permissions) {
			await db.delete(permissions).where(eq(permissions.agentId, agentId));
			if (input.permissions.length > 0) {
				await db.insert(permissions).values(
					input.permissions.map((p) => ({
						id: randomUUID(),
						agentId,
						resource: p.resource,
						actions: p.actions,
						constraints: p.constraints ?? null,
						createdAt: now,
					})),
				);
			}
		}

		const updated = await get(agentId);
		if (!updated) throw new Error(`Agent ${agentId} disappeared after update.`);
		return updated;
	}

	async function revoke(agentId: string): Promise<void> {
		const existing = await get(agentId);
		if (!existing) throw new Error(`Agent ${agentId} not found.`);

		await db
			.update(agents)
			.set({ status: "revoked", updatedAt: new Date() })
			.where(eq(agents.id, agentId));
	}

	async function rotate(agentId: string): Promise<AgentIdentity & { token: string }> {
		const existing = await get(agentId);
		if (!existing) throw new Error(`Agent ${agentId} not found.`);
		if (existing.status !== "active")
			throw new Error(`Cannot rotate token for ${existing.status} agent.`);

		const { token, hash, prefix } = generateAgentToken();
		const now = new Date();

		await db
			.update(agents)
			.set({ tokenHash: hash, tokenPrefix: prefix, updatedAt: now })
			.where(eq(agents.id, agentId));

		return { ...existing, token, updatedAt: now };
	}

	/**
	 * Validate an agent token and return the agent identity.
	 * Used internally by the authorization engine.
	 */
	async function validateToken(token: string): Promise<AgentIdentity | null> {
		const hash = createHash("sha256").update(token).digest("hex");
		const rows = await db.select().from(agents).where(eq(agents.tokenHash, hash)).limit(1);
		const agent = rows[0];
		if (!agent) return null;

		// Check status
		if (agent.status !== "active") return null;

		// Check expiry
		if (agent.expiresAt && agent.expiresAt < new Date()) {
			await db
				.update(agents)
				.set({ status: "expired", updatedAt: new Date() })
				.where(eq(agents.id, agent.id));
			return null;
		}

		// Update last active
		await db.update(agents).set({ lastActiveAt: new Date() }).where(eq(agents.id, agent.id));

		const perms = await db.select().from(permissions).where(eq(permissions.agentId, agent.id));

		return {
			id: agent.id,
			ownerId: agent.ownerId,
			tenantId: agent.tenantId ?? undefined,
			name: agent.name,
			type: agent.type as AgentIdentity["type"],
			token: "",
			permissions: perms.map(toPermission),
			status: "active",
			expiresAt: agent.expiresAt,
			createdAt: agent.createdAt,
			updatedAt: agent.updatedAt,
		};
	}

	return { create, get, list, update, revoke, rotate, validateToken };
}

function toPermission(row: {
	resource: string;
	actions: string[];
	constraints: unknown;
}): Permission {
	return {
		resource: row.resource,
		actions: row.actions,
		constraints: (row.constraints as Permission["constraints"]) ?? undefined,
	};
}
