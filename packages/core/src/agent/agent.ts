import { and, eq, ne } from "drizzle-orm";
import { recordAuditEvent } from "../audit/record.js";
import { generateId, randomBytes, sha256, toBase64Url } from "../crypto/web-crypto.js";
import type { Database } from "../db/database.js";
import { agents, permissions } from "../db/schema.js";
import { createDelegationModule } from "../delegation/delegation.js";
import { revocationRowExpiry } from "../mcp/revocation-bus.js";
import type { McpRevocationBus } from "../mcp/revocation-types.js";
import type { ResourceMatching } from "../policy/resource-match.js";
import type {
	AgentFilter,
	AgentIdentity,
	CreateAgentInput,
	Permission,
	UpdateAgentInput,
} from "../types.js";
import { assertValidExpiry } from "../validation.js";
import type { AgentConfirmation } from "./confirmation.js";
import { parseConfirmation, readStoredConfirmation } from "./confirmation.js";
import { AGENT_TOKEN_PREFIX, agentTokenLookupPrefix, isAgentToken } from "./token-format.js";

interface AgentModuleConfig {
	db: Database;
	maxPerUser: number;
	defaultPermissions: string[];
	tokenExpiry: string;
	/** Receives agent and cascaded delegation revocations for the shared MCP denylist. Optional. */
	revocations?: McpRevocationBus;
	/** Top level `resourceMatching`, used by delegation subset checks. */
	resourceMatching?: ResourceMatching;
}

/**
 * Generate a secure agent token. Returns { token, hash, prefix } where:
 * - token: the full token (given to the agent, never stored)
 * - hash: SHA-256 hash (stored in DB)
 * - prefix: prefix plus first 8 chars (for identification in logs/UI)
 */
async function generateAgentToken(): Promise<{ token: string; hash: string; prefix: string }> {
	const tokenBytes = randomBytes(32);
	const token = `${AGENT_TOKEN_PREFIX}${toBase64Url(tokenBytes)}`;
	const hash = await sha256(token);
	const prefix = agentTokenLookupPrefix(token); // "ta_" + 8 chars
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

/** Create the agent identity module. Handles CRUD operations for AI agent identities. */
export function createAgentModule(config: AgentModuleConfig) {
	const { db, maxPerUser, tokenExpiry, revocations } = config;
	const delegation = createDelegationModule({
		db,
		revocations,
		resourceMatching: config.resourceMatching,
	});

	async function create(input: CreateAgentInput): Promise<AgentIdentity & { token: string }> {
		assertValidExpiry(input.expiresAt);
		if (input.type === "device") {
			throw new Error('Agents of type "device" are created with theauth.device.register().');
		}
		// Check max agents per user
		const existing = await db
			.select()
			.from(agents)
			.where(
				and(
					eq(agents.ownerId, input.ownerId),
					eq(agents.status, "active"),
					// Device backing agents have their own cap (devices.maxPerOwner).
					ne(agents.type, "device"),
				),
			);

		if (existing.length >= maxPerUser) {
			throw new Error(
				`User ${input.ownerId} has reached the maximum of ${maxPerUser} active agents.`,
			);
		}

		const cnf = input.cnf === undefined ? undefined : parseConfirmation(input.cnf);
		const id = generateId();
		const { token, hash, prefix } = await generateAgentToken();
		const now = new Date();
		const expires = input.expiresAt ?? parseTokenExpiry(tokenExpiry);

		await db.insert(agents).values({
			id,
			ownerId: input.ownerId,
			tenantId: input.tenantId ?? null,
			name: input.name,
			type: input.type,
			status: "active",
			tokenHash: hash,
			tokenPrefix: prefix,
			cnf: cnf ?? null,
			expiresAt: expires,
			metadata: input.metadata ?? {},
			createdAt: now,
			updatedAt: now,
		});

		if (input.permissions.length > 0) {
			await db.insert(permissions).values(
				input.permissions.map((p) => ({
					id: generateId(),
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
			...(cnf ? { cnf } : {}),
			createdAt: now,
			updatedAt: now,
		};
	}

	async function get(agentId: string): Promise<AgentIdentity | null> {
		// Both reads are independent of each other, so they overlap on a driver with network latency.
		const [rows, perms] = await Promise.all([
			db.select().from(agents).where(eq(agents.id, agentId)).limit(1),
			db.select().from(permissions).where(eq(permissions.agentId, agentId)),
		]);
		const agent = rows[0];
		if (!agent) return null;

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
			...cnfField(agent.cnf),
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
		// Device backing agents are listed only when asked for: they are managed through `device.*`.
		if (filter?.type) conditions.push(eq(agents.type, filter.type));
		else conditions.push(ne(agents.type, "device"));

		query = query.where(and(...conditions));

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
			...cnfField(agent.cnf),
			createdAt: agent.createdAt,
			updatedAt: agent.updatedAt,
		}));
	}

	async function update(agentId: string, input: UpdateAgentInput): Promise<AgentIdentity> {
		assertValidExpiry(input.expiresAt);
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
						id: generateId(),
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

	/**
	 * Revoke an agent, then every active delegation chain where it is source or target (and their child chains). The agent is revoked first so a failure part way leaves the agent unusable. One `agent.cascade.revoked` audit row lists the revoked chain ids. Calling it again revokes nothing new and writes no row.
	 */
	async function revoke(agentId: string): Promise<{ revokedDelegations: string[] }> {
		const existing = await get(agentId);
		if (!existing) throw new Error(`Agent ${agentId} not found.`);

		await db
			.update(agents)
			.set({ status: "revoked", updatedAt: new Date() })
			.where(eq(agents.id, agentId));

		// Tokens bound to this agent die now; the bound delegations are pushed by the delegation module.
		if (revocations) {
			const now = new Date();
			try {
				await revocations.publish(
					{
						kind: "agent",
						ids: [agentId],
						revokedAt: now,
						reason: "agent.revoke",
						userId: existing.ownerId,
						sourceId: agentId,
					},
					[
						{
							kind: "agent",
							id: agentId,
							expiresAt: revocationRowExpiry(existing.expiresAt, now),
							reason: "agent.revoke",
							sourceId: agentId,
						},
					],
				);
			} catch {
				// The bus reports its own failures; the agent row is already revoked.
			}
		}

		const revokedDelegations = await delegation.revokeAllForAgent(agentId);
		if (revokedDelegations.length > 0) {
			await recordAuditEvent(db, {
				agentId,
				userId: existing.ownerId,
				action: "agent.cascade.revoked",
				resource: `agent:${agentId}`,
				result: "allowed",
				delegationChain: revokedDelegations,
				parameters: { agentId, revokedDelegations, count: revokedDelegations.length },
			});
		}
		return { revokedDelegations };
	}

	/**
	 * Replace the agent token. The new token keeps the old `cnf` binding, so a stolen token is replaced by one the thief cannot use either. Pass `cnf` to bind to a new key or certificate, or `null` to make the token a plain bearer token again.
	 */
	async function rotate(
		agentId: string,
		options: { cnf?: AgentConfirmation | null } = {},
	): Promise<AgentIdentity & { token: string }> {
		const existing = await get(agentId);
		if (!existing) throw new Error(`Agent ${agentId} not found.`);
		if (existing.status !== "active")
			throw new Error(`Cannot rotate token for ${existing.status} agent.`);
		// A device backing agent has no usable bearer token; devices authenticate with device credentials.
		if (existing.type === "device")
			throw new Error("Cannot rotate the token of a device agent. Use device credentials instead.");

		const { token, hash, prefix } = await generateAgentToken();
		const now = new Date();

		const rebind =
			options.cnf === undefined
				? undefined
				: options.cnf === null
					? null
					: parseConfirmation(options.cnf);
		await db
			.update(agents)
			.set({
				tokenHash: hash,
				tokenPrefix: prefix,
				updatedAt: now,
				...(rebind !== undefined && { cnf: rebind }),
			})
			.where(eq(agents.id, agentId));

		const { cnf: _previous, ...rest } = existing;
		const cnf = rebind === undefined ? existing.cnf : (rebind ?? undefined);
		return { ...rest, ...(cnf ? { cnf } : {}), token, updatedAt: now };
	}

	/**
	 * Look up an agent by token and say why it was refused when it was. `rejected` is set only when the token matches a known agent that is revoked or expired, so the caller can record the denied attempt. An unknown token yields `{ agent: null }` with no `rejected`.
	 */
	async function resolveToken(token: string): Promise<{
		agent: AgentIdentity | null;
		rejected?: { agentId: string; ownerId: string; reason: "revoked" | "expired" };
	}> {
		// Unknown prefix: cannot be one of ours, skip the hash and the DB lookup.
		if (!isAgentToken(token)) return { agent: null };
		const hash = await sha256(token);
		const rows = await db.select().from(agents).where(eq(agents.tokenHash, hash)).limit(1);
		const agent = rows[0];
		if (!agent) return { agent: null };

		if (agent.status !== "active") {
			return {
				agent: null,
				rejected: {
					agentId: agent.id,
					ownerId: agent.ownerId,
					reason: agent.status === "expired" ? "expired" : "revoked",
				},
			};
		}

		if (agent.expiresAt && agent.expiresAt < new Date()) {
			await db
				.update(agents)
				.set({ status: "expired", updatedAt: new Date() })
				.where(eq(agents.id, agent.id));
			return {
				agent: null,
				rejected: { agentId: agent.id, ownerId: agent.ownerId, reason: "expired" },
			};
		}

		await db.update(agents).set({ lastActiveAt: new Date() }).where(eq(agents.id, agent.id));

		const perms = await db.select().from(permissions).where(eq(permissions.agentId, agent.id));

		return {
			agent: {
				id: agent.id,
				ownerId: agent.ownerId,
				tenantId: agent.tenantId ?? undefined,
				name: agent.name,
				type: agent.type as AgentIdentity["type"],
				token: "",
				permissions: perms.map(toPermission),
				status: "active",
				expiresAt: agent.expiresAt,
				...cnfField(agent.cnf),
				createdAt: agent.createdAt,
				updatedAt: agent.updatedAt,
			},
		};
	}

	/** Validate an agent token and return the agent identity. Used internally by the authorization engine. */
	async function validateToken(token: string): Promise<AgentIdentity | null> {
		return (await resolveToken(token)).agent;
	}

	return { create, get, list, update, revoke, rotate, validateToken, resolveToken };
}

/** The `cnf` member of an identity, or nothing for a plain bearer token. */
function cnfField(raw: unknown): { cnf?: AgentConfirmation } {
	const cnf = readStoredConfirmation(raw);
	return cnf ? { cnf } : {};
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
