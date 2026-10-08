/**
 * Agent registration tokens.
 *
 * A human (or an admin) mints a short-lived, single-use token that carries a
 * fixed set of permissions. A headless agent or CLI redeems it once to create
 * its own agent identity, with no human session on the agent's side. The token
 * is returned once and stored as a SHA-256 hash. The bearer can choose the
 * agent's name but cannot widen its permissions, type or owner.
 *
 * @example
 * ```typescript
 * const registration = createAgentRegistrationModule({ db, agents: agentModule });
 * const minted = await registration.create({
 *   ownerId: user.id,
 *   permissions: [{ resource: 'mcp:github:*', actions: ['read'] }],
 *   expiresInSeconds: 600,
 * });
 * // hand minted.data.token to the agent, then on the agent side:
 * const agent = await registration.redeem(token, { name: 'ci-bot' });
 * ```
 */

import { and, desc, eq, gt, isNull } from "drizzle-orm";
import { generateId, randomBytes, sha256, toBase64Url } from "../crypto/web-crypto.js";
import type { Database } from "../db/database.js";
import { agentRegistrationTokens, auditLogs } from "../db/schema.js";
import type { TheAuthError } from "../mcp/types.js";
import type { AgentIdentity, CreateAgentInput, Permission } from "../types.js";

export type RegistrationResult<T> =
	| { success: true; data: T }
	| { success: false; error: TheAuthError };

export type AgentType = CreateAgentInput["type"];

export interface AgentRegistrationConfig {
	db: Database;
	/** The agent module's `create` (what `createTheAuth` exposes as `theauth.agents.create`). */
	agents: { create: (input: CreateAgentInput) => Promise<AgentIdentity> };
	/** Default token lifetime, seconds (default 900). */
	defaultExpiresInSeconds?: number;
	/** Longest lifetime an issuer may request, seconds (default 604800 = 7 days). */
	maxExpiresInSeconds?: number;
	/** Receives create / revoke / redeem events. Wire it to your audit sink. */
	onEvent?: (event: AgentRegistrationEvent) => void | Promise<void>;
}

export interface AgentRegistrationEvent {
	type:
		| "agent_registration.token_created"
		| "agent_registration.token_revoked"
		| "agent_registration.redeemed"
		| "agent_registration.redeem_failed";
	tokenId?: string;
	ownerId?: string;
	actorId?: string;
	agentId?: string;
	reason?: string;
}

export interface CreateRegistrationTokenInput {
	/** User who will own the agent created with this token. */
	ownerId: string;
	/** Permissions the registered agent receives. Fixed at mint time. */
	permissions: Permission[];
	label?: string;
	agentType?: AgentType;
	tenantId?: string;
	/** Registered agent names must start with this. */
	namePrefix?: string;
	expiresInSeconds?: number;
	/** Lifetime of the agent token issued on redemption, seconds. */
	agentTtlSeconds?: number;
	/** Who minted it, for the audit trail. */
	createdBy?: string;
}

export interface CreatedRegistrationToken {
	id: string;
	/** The raw token. Shown once, never stored. */
	token: string;
	prefix: string;
	expiresAt: Date;
}

export type RegistrationTokenStatus = "active" | "used" | "revoked" | "expired";

export interface RegistrationTokenRecord {
	id: string;
	prefix: string;
	label: string | null;
	ownerId: string;
	tenantId: string | null;
	agentType: AgentType;
	permissions: Permission[];
	namePrefix: string | null;
	status: RegistrationTokenStatus;
	createdBy: string | null;
	createdAt: Date;
	expiresAt: Date;
	usedAt: Date | null;
	agentId: string | null;
}

export interface RedeemInput {
	name: string;
	metadata?: Record<string, unknown>;
}

export interface AgentRegistrationModule {
	create(
		input: CreateRegistrationTokenInput,
	): Promise<RegistrationResult<CreatedRegistrationToken>>;
	list(filter?: {
		ownerId?: string;
		status?: RegistrationTokenStatus;
	}): Promise<RegistrationTokenRecord[]>;
	revoke(id: string, actorId?: string): Promise<RegistrationResult<{ id: string }>>;
	redeem(
		token: string,
		input: RedeemInput,
	): Promise<RegistrationResult<AgentIdentity & { token: string }>>;
}

const TOKEN_PREFIX = "kvr_";
const DEFAULT_EXPIRES_SECONDS = 900;
const MAX_EXPIRES_SECONDS = 604_800;
const MAX_NAME_LENGTH = 128;

function fail<T>(code: string, message: string): RegistrationResult<T> {
	return { success: false, error: { code, message } };
}

function statusOf(row: {
	revokedAt: Date | null;
	usedAt: Date | null;
	expiresAt: Date;
}): RegistrationTokenStatus {
	if (row.revokedAt) return "revoked";
	if (row.usedAt) return "used";
	return row.expiresAt.getTime() <= Date.now() ? "expired" : "active";
}

export function createAgentRegistrationModule(
	config: AgentRegistrationConfig,
): AgentRegistrationModule {
	const { db } = config;
	const defaultTtl = config.defaultExpiresInSeconds ?? DEFAULT_EXPIRES_SECONDS;
	const maxTtl = config.maxExpiresInSeconds ?? MAX_EXPIRES_SECONDS;

	async function emit(event: AgentRegistrationEvent): Promise<void> {
		try {
			await config.onEvent?.(event);
		} catch {
			// An audit sink failure must not decide whether auth succeeds.
		}
	}

	async function create(
		input: CreateRegistrationTokenInput,
	): Promise<RegistrationResult<CreatedRegistrationToken>> {
		const ttl = input.expiresInSeconds ?? defaultTtl;
		if (!Number.isFinite(ttl) || ttl <= 0 || ttl > maxTtl) {
			return fail("INVALID_EXPIRY", `expiresInSeconds must be between 1 and ${maxTtl}`);
		}
		if (input.permissions.length === 0) {
			return fail("INVALID_PERMISSIONS", "A registration token must grant at least one permission");
		}

		const token = `${TOKEN_PREFIX}${toBase64Url(randomBytes(32))}`;
		const id = generateId();
		const now = new Date();
		const expiresAt = new Date(now.getTime() + ttl * 1000);
		const prefix = token.slice(0, TOKEN_PREFIX.length + 6);

		await db.insert(agentRegistrationTokens).values({
			id,
			tokenHash: await sha256(token),
			tokenPrefix: prefix,
			label: input.label ?? null,
			ownerId: input.ownerId,
			tenantId: input.tenantId ?? null,
			agentType: input.agentType ?? "autonomous",
			permissions: input.permissions,
			namePrefix: input.namePrefix ?? null,
			agentTtlSeconds: input.agentTtlSeconds ?? null,
			createdBy: input.createdBy ?? null,
			expiresAt,
			createdAt: now,
		});

		await emit({
			type: "agent_registration.token_created",
			tokenId: id,
			ownerId: input.ownerId,
			actorId: input.createdBy,
		});
		return { success: true, data: { id, token, prefix, expiresAt } };
	}

	async function list(
		filter: { ownerId?: string; status?: RegistrationTokenStatus } = {},
	): Promise<RegistrationTokenRecord[]> {
		const rows = await db
			.select()
			.from(agentRegistrationTokens)
			.where(filter.ownerId ? eq(agentRegistrationTokens.ownerId, filter.ownerId) : undefined)
			.orderBy(desc(agentRegistrationTokens.createdAt));

		return rows
			.map((row) => ({
				id: row.id,
				prefix: row.tokenPrefix,
				label: row.label,
				ownerId: row.ownerId,
				tenantId: row.tenantId,
				agentType: row.agentType as AgentType,
				permissions: row.permissions as Permission[],
				namePrefix: row.namePrefix,
				status: statusOf(row),
				createdBy: row.createdBy,
				createdAt: row.createdAt,
				expiresAt: row.expiresAt,
				usedAt: row.usedAt,
				agentId: row.agentId,
			}))
			.filter((r) => !filter.status || r.status === filter.status);
	}

	async function revoke(id: string, actorId?: string): Promise<RegistrationResult<{ id: string }>> {
		const rows = await db
			.select()
			.from(agentRegistrationTokens)
			.where(eq(agentRegistrationTokens.id, id))
			.limit(1);
		const row = rows[0];
		if (!row) return fail("TOKEN_NOT_FOUND", "Registration token not found");
		if (row.usedAt) return fail("TOKEN_ALREADY_USED", "Token was already redeemed");
		if (!row.revokedAt) {
			await db
				.update(agentRegistrationTokens)
				.set({ revokedAt: new Date() })
				.where(and(eq(agentRegistrationTokens.id, id), isNull(agentRegistrationTokens.revokedAt)));
			await emit({
				type: "agent_registration.token_revoked",
				tokenId: id,
				ownerId: row.ownerId,
				actorId,
			});
		}
		return { success: true, data: { id } };
	}

	async function redeem(
		token: string,
		input: RedeemInput,
	): Promise<RegistrationResult<AgentIdentity & { token: string }>> {
		const denied = async (reason: string, tokenId?: string, ownerId?: string) => {
			await emit({ type: "agent_registration.redeem_failed", tokenId, ownerId, reason });
		};

		if (!token.startsWith(TOKEN_PREFIX)) {
			await denied("malformed_token");
			return fail("INVALID_TOKEN", "Invalid or expired registration token");
		}
		const name = input.name?.trim();
		if (!name || name.length > MAX_NAME_LENGTH) {
			return fail("INVALID_NAME", `Agent name is required (max ${MAX_NAME_LENGTH} characters)`);
		}

		const tokenHash = await sha256(token);
		const rows = await db
			.select()
			.from(agentRegistrationTokens)
			.where(eq(agentRegistrationTokens.tokenHash, tokenHash))
			.limit(1);
		const row = rows[0];
		// One message for every unusable state so the endpoint is not an oracle.
		if (!row || statusOf(row) !== "active") {
			await denied(row ? `token_${statusOf(row)}` : "unknown_token", row?.id, row?.ownerId);
			return fail("INVALID_TOKEN", "Invalid or expired registration token");
		}
		if (row.namePrefix && !name.startsWith(row.namePrefix)) {
			return fail("INVALID_NAME", `Agent name must start with "${row.namePrefix}"`);
		}

		// Claim: exactly one caller can flip used_at from null, and only the
		// caller whose nonce landed proceeds.
		const nonce = generateId();
		await db
			.update(agentRegistrationTokens)
			.set({ usedAt: new Date(), claimNonce: nonce })
			.where(
				and(
					eq(agentRegistrationTokens.id, row.id),
					isNull(agentRegistrationTokens.usedAt),
					isNull(agentRegistrationTokens.revokedAt),
					gt(agentRegistrationTokens.expiresAt, new Date()),
				),
			);
		const claimed = await db
			.select()
			.from(agentRegistrationTokens)
			.where(eq(agentRegistrationTokens.id, row.id))
			.limit(1);
		if (claimed[0]?.claimNonce !== nonce) {
			await denied("token_already_used", row.id, row.ownerId);
			return fail("INVALID_TOKEN", "Invalid or expired registration token");
		}

		try {
			const agent = await config.agents.create({
				ownerId: row.ownerId,
				tenantId: row.tenantId ?? undefined,
				name,
				type: row.agentType as AgentType,
				permissions: row.permissions as Permission[],
				expiresAt: row.agentTtlSeconds
					? new Date(Date.now() + row.agentTtlSeconds * 1000)
					: undefined,
				metadata: {
					...(input.metadata ?? {}),
					registeredVia: "registration_token",
					tokenId: row.id,
				},
			});
			const created = agent as AgentIdentity & { token: string };

			await db
				.update(agentRegistrationTokens)
				.set({ agentId: created.id })
				.where(eq(agentRegistrationTokens.id, row.id));
			try {
				await db.insert(auditLogs).values({
					id: generateId(),
					agentId: created.id,
					userId: row.ownerId,
					action: "register",
					resource: `agent_registration_token:${row.id}`,
					parameters: { name, createdBy: row.createdBy },
					result: "allowed",
					reason: null,
					durationMs: 0,
					timestamp: new Date(),
				});
			} catch {
				// The agent exists; a failed audit row is reported through onEvent below.
			}
			await emit({
				type: "agent_registration.redeemed",
				tokenId: row.id,
				ownerId: row.ownerId,
				agentId: created.id,
			});
			return { success: true, data: created };
		} catch (err) {
			// Give the token back so the issuer's work is not lost to a transient
			// failure (for example the owner hitting the agent limit).
			await db
				.update(agentRegistrationTokens)
				.set({ usedAt: null, claimNonce: null })
				.where(
					and(
						eq(agentRegistrationTokens.id, row.id),
						eq(agentRegistrationTokens.claimNonce, nonce),
					),
				);
			await denied("agent_create_failed", row.id, row.ownerId);
			return fail(
				"AGENT_CREATE_FAILED",
				err instanceof Error ? err.message : "Could not create agent",
			);
		}
	}

	return { create, list, revoke, redeem };
}
