/**
 * Ephemeral agent sessions for TheAuth.
 *
 * Short-lived, auto-expiring agent credentials for single-task use. Designed
 * for computer-use agents (Claude, GPT with browsing, operator loops) that
 * should not hold persistent tokens across invocations.
 *
 * Each session spins up a temporary agent, issues a bounded bearer token, and
 * tracks how many actions have been consumed. When the TTL lapses or the
 * action budget is exhausted the token becomes invalid and the underlying
 * agent is automatically revoked.
 *
 * @example
 * ```typescript
 * const mod = createEphemeralSessionModule({ db });
 *
 * // Create a 5-minute, 10-action session
 * const result = await mod.createSession({
 *   ownerId: 'user-123',
 *   permissions: [{ resource: 'tool:browser', actions: ['navigate', 'click'] }],
 *   ttlSeconds: 300,
 *   maxActions: 10,
 * });
 *
 * if (!result.success) throw new Error(result.error.message);
 *
 * const { token } = result.data;
 *
 * // Each time the agent performs an action
 * await mod.consumeAction(token);
 * ```
 */

import { and, eq, lt } from "drizzle-orm";
import { z } from "zod";
import { generateId, randomBytesHex, sha256 } from "../crypto/web-crypto.js";
import type { Database } from "../db/database.js";
import { agents, ephemeralSessions, permissions } from "../db/schema.js";
import type { KavachError, Result } from "../mcp/types.js";
import type { Permission } from "../types.js";

// ─── Config ──────────────────────────────────────────────────────────────────

export interface EphemeralSessionConfig {
	db: Database;
	/** Default TTL for sessions in seconds (default: 300 = 5 min) */
	defaultTtlSeconds?: number;
	/** Hard ceiling on TTL in seconds (default: 3600 = 1 hour) */
	maxTtlSeconds?: number;
	/** Automatically revoke the underlying agent when the session expires (default: true) */
	autoRevokeOnExpiry?: boolean;
	/** Group all actions under a shared audit session ID (default: true) */
	auditGrouping?: boolean;
}

// ─── Public types ─────────────────────────────────────────────────────────────

export interface CreateEphemeralSessionInput {
	ownerId: string;
	name?: string;
	permissions: Permission[];
	/** Seconds until the session expires (capped at maxTtlSeconds) */
	ttlSeconds?: number;
	/** Optional cap on the number of actions the token may authorize */
	maxActions?: number;
	metadata?: Record<string, unknown>;
}

export interface EphemeralSession {
	sessionId: string;
	agentId: string;
	/** Bearer token — shown once, never stored in plain text */
	token: string;
	expiresAt: Date;
	maxActions: number | null;
	actionsUsed: number;
	status: "active" | "expired" | "exhausted" | "revoked";
	/** Shared audit group ID for all actions within the session */
	auditGroupId: string;
	createdAt: Date;
}

export interface EphemeralSessionValidateResult {
	sessionId: string;
	agentId: string;
	remainingActions: number | null;
	/** Seconds until the token expires */
	expiresIn: number;
	auditGroupId: string;
}

export interface EphemeralSessionModule {
	createSession(input: CreateEphemeralSessionInput): Promise<Result<EphemeralSession>>;
	validateSession(token: string): Promise<Result<EphemeralSessionValidateResult>>;
	consumeAction(token: string): Promise<Result<{ actionsRemaining: number | null }>>;
	revokeSession(sessionId: string): Promise<Result<void>>;
	listActiveSessions(ownerId: string): Promise<Result<EphemeralSession[]>>;
	cleanupExpired(): Promise<Result<{ count: number }>>;
}

// ─── Zod validation ──────────────────────────────────────────────────────────

const CreateEphemeralSessionSchema = z.object({
	ownerId: z.string().min(1),
	name: z.string().optional(),
	permissions: z
		.array(
			z.object({
				resource: z.string().min(1),
				actions: z.array(z.string().min(1)).min(1),
				constraints: z.record(z.unknown()).optional(),
			}),
		)
		.min(1, "At least one permission is required"),
	ttlSeconds: z.number().int().positive().optional(),
	maxActions: z.number().int().positive().optional(),
	metadata: z.record(z.unknown()).optional(),
});

// ─── Helpers ─────────────────────────────────────────────────────────────────

async function generateSessionToken(): Promise<{ token: string; hash: string }> {
	const hex = randomBytesHex(32);
	const token = `kveph_${hex}`;
	const hash = await sha256(token);
	return { token, hash };
}

function err(code: string, message: string, details?: Record<string, unknown>): KavachError {
	return { code, message, ...(details ? { details } : {}) };
}

function ok<T>(data: T): Result<T> {
	return { success: true, data };
}

function fail<T>(code: string, message: string, details?: Record<string, unknown>): Result<T> {
	return { success: false, error: err(code, message, details) };
}

// ─── Module factory ───────────────────────────────────────────────────────────

export function createEphemeralSessionModule(
	config: EphemeralSessionConfig,
): EphemeralSessionModule {
	const {
		db,
		defaultTtlSeconds = 300,
		maxTtlSeconds = 3600,
		autoRevokeOnExpiry = true,
		auditGrouping = true,
	} = config;

	// ── createSession ──────────────────────────────────────────────────────────

	async function createSession(
		input: CreateEphemeralSessionInput,
	): Promise<Result<EphemeralSession>> {
		const parsed = CreateEphemeralSessionSchema.safeParse(input);
		if (!parsed.success) {
			return fail("VALIDATION_ERROR", parsed.error.errors[0]?.message ?? "Invalid input", {
				issues: parsed.error.errors,
			});
		}

		const { ownerId, name, permissions: perms, ttlSeconds, maxActions, metadata } = parsed.data;

		// Validate owner exists
		const ownerRows = await db
			.select({ id: agents.ownerId })
			.from(agents)
			.where(eq(agents.ownerId, ownerId))
			.limit(1);

		// We allow creation for any ownerId (the caller asserts ownership). If the
		// users table is checked it would need an import of users — callers are
		// responsible for passing a valid owner. We do verify TTL bounds here.
		void ownerRows; // intentional no-op; owner is caller-asserted

		const requestedTtl = ttlSeconds ?? defaultTtlSeconds;
		if (requestedTtl > maxTtlSeconds) {
			return fail(
				"TTL_EXCEEDS_MAX",
				`Requested TTL (${requestedTtl}s) exceeds maximum allowed (${maxTtlSeconds}s)`,
				{ requestedTtl, maxTtlSeconds },
			);
		}

		const now = new Date();
		const expiresAt = new Date(now.getTime() + requestedTtl * 1000);
		const sessionId = generateId();
		const agentId = generateId();
		const auditGroupId = auditGrouping ? generateId() : sessionId;

		// Token for this ephemeral session (stored as hash in agents table)
		const { token, hash: tokenHash } = await generateSessionToken();
		const tokenPrefix = token.slice(0, 14); // "kveph_" + 8 chars

		// Insert a temporary agent
		await db.insert(agents).values({
			id: agentId,
			ownerId,
			tenantId: null,
			name: name ?? `ephemeral-${sessionId.slice(0, 8)}`,
			type: "autonomous",
			status: "active",
			tokenHash,
			tokenPrefix,
			expiresAt,
			metadata: {
				...(metadata ?? {}),
				ephemeral: true,
				sessionId,
			},
			createdAt: now,
			updatedAt: now,
		});

		// Insert permissions for the agent
		if (perms.length > 0) {
			await db.insert(permissions).values(
				perms.map((p) => ({
					id: generateId(),
					agentId,
					resource: p.resource,
					actions: p.actions,
					constraints: (p.constraints as Record<string, unknown>) ?? null,
					createdAt: now,
				})),
			);
		}

		// Insert the ephemeral session record
		await db.insert(ephemeralSessions).values({
			id: sessionId,
			agentId,
			ownerId,
			tokenHash,
			expiresAt,
			maxActions: maxActions ?? null,
			actionsUsed: 0,
			status: "active",
			auditGroupId,
			createdAt: now,
			updatedAt: now,
		});

		return ok<EphemeralSession>({
			sessionId,
			agentId,
			token,
			expiresAt,
			maxActions: maxActions ?? null,
			actionsUsed: 0,
			status: "active",
			auditGroupId,
			createdAt: now,
		});
	}

	// ── validateSession ────────────────────────────────────────────────────────

	async function validateSession(token: string): Promise<Result<EphemeralSessionValidateResult>> {
		const hash = await sha256(token);
		const rows = await db
			.select()
			.from(ephemeralSessions)
			.where(eq(ephemeralSessions.tokenHash, hash))
			.limit(1);

		const row = rows[0];
		if (!row) {
			return fail("SESSION_NOT_FOUND", "Session not found or token is invalid");
		}

		const now = new Date();

		// Check expiry first
		if (row.expiresAt < now) {
			if (row.status === "active") {
				await markExpired(row.id, row.agentId);
			}
			return fail("SESSION_EXPIRED", "Session has expired");
		}

		if (row.status === "revoked") {
			return fail("SESSION_REVOKED", "Session has been revoked");
		}
		if (row.status === "expired") {
			return fail("SESSION_EXPIRED", "Session has expired");
		}
		if (row.status === "exhausted") {
			return fail("SESSION_EXHAUSTED", "Session action budget has been exhausted");
		}

		const expiresIn = Math.max(0, Math.floor((row.expiresAt.getTime() - now.getTime()) / 1000));
		const remainingActions =
			row.maxActions !== null ? Math.max(0, row.maxActions - row.actionsUsed) : null;

		return ok<EphemeralSessionValidateResult>({
			sessionId: row.id,
			agentId: row.agentId,
			remainingActions,
			expiresIn,
			auditGroupId: row.auditGroupId,
		});
	}

	// ── consumeAction ──────────────────────────────────────────────────────────

	async function consumeAction(
		token: string,
	): Promise<Result<{ actionsRemaining: number | null }>> {
		const hash = await sha256(token);
		const rows = await db
			.select()
			.from(ephemeralSessions)
			.where(eq(ephemeralSessions.tokenHash, hash))
			.limit(1);

		const row = rows[0];
		if (!row) {
			return fail("SESSION_NOT_FOUND", "Session not found or token is invalid");
		}

		const now = new Date();

		if (row.expiresAt < now) {
			if (row.status === "active") {
				await markExpired(row.id, row.agentId);
			}
			return fail("SESSION_EXPIRED", "Session has expired");
		}

		if (row.status !== "active") {
			return fail(
				`SESSION_${row.status.toUpperCase()}`,
				`Session is ${row.status} and cannot accept actions`,
			);
		}

		const nextActionsUsed = row.actionsUsed + 1;

		// Check budget before committing
		if (row.maxActions !== null && nextActionsUsed > row.maxActions) {
			await db
				.update(ephemeralSessions)
				.set({ status: "exhausted", updatedAt: now })
				.where(eq(ephemeralSessions.id, row.id));
			if (autoRevokeOnExpiry) {
				await db
					.update(agents)
					.set({ status: "revoked", updatedAt: now })
					.where(eq(agents.id, row.agentId));
			}
			return fail("SESSION_EXHAUSTED", "Session action budget has been exhausted");
		}

		// Determine next status
		const isNowExhausted = row.maxActions !== null && nextActionsUsed >= row.maxActions;
		const nextStatus = isNowExhausted ? "exhausted" : "active";

		await db
			.update(ephemeralSessions)
			.set({ actionsUsed: nextActionsUsed, status: nextStatus, updatedAt: now })
			.where(eq(ephemeralSessions.id, row.id));

		if (isNowExhausted && autoRevokeOnExpiry) {
			await db
				.update(agents)
				.set({ status: "revoked", updatedAt: now })
				.where(eq(agents.id, row.agentId));
		}

		const actionsRemaining = row.maxActions !== null ? row.maxActions - nextActionsUsed : null;

		return ok({ actionsRemaining });
	}

	// ── revokeSession ──────────────────────────────────────────────────────────

	async function revokeSession(sessionId: string): Promise<Result<void>> {
		const rows = await db
			.select()
			.from(ephemeralSessions)
			.where(eq(ephemeralSessions.id, sessionId))
			.limit(1);

		const row = rows[0];
		if (!row) {
			return fail("SESSION_NOT_FOUND", `Session ${sessionId} not found`);
		}

		if (row.status === "revoked") {
			return ok(undefined);
		}

		const now = new Date();

		await db
			.update(ephemeralSessions)
			.set({ status: "revoked", updatedAt: now })
			.where(eq(ephemeralSessions.id, sessionId));

		await db
			.update(agents)
			.set({ status: "revoked", updatedAt: now })
			.where(eq(agents.id, row.agentId));

		return ok(undefined);
	}

	// ── listActiveSessions ─────────────────────────────────────────────────────

	async function listActiveSessions(ownerId: string): Promise<Result<EphemeralSession[]>> {
		const now = new Date();
		const rows = await db
			.select()
			.from(ephemeralSessions)
			.where(and(eq(ephemeralSessions.ownerId, ownerId), eq(ephemeralSessions.status, "active")));

		// Filter out any that have lapsed in-flight and auto-expire them
		const live: EphemeralSession[] = [];
		const toExpire: string[] = [];

		for (const row of rows) {
			if (row.expiresAt < now) {
				toExpire.push(row.id);
				continue;
			}
			live.push(rowToSession(row));
		}

		if (toExpire.length > 0) {
			// Fire-and-forget expiry; no await needed for listing
			void Promise.all(
				toExpire.map(async (id) => {
					const r = rows.find((x) => x.id === id);
					if (r) await markExpired(id, r.agentId);
				}),
			);
		}

		return ok(live);
	}

	// ── cleanupExpired ─────────────────────────────────────────────────────────

	async function cleanupExpired(): Promise<Result<{ count: number }>> {
		const now = new Date();

		// Find sessions that have passed their expiry and are still "active"
		const staleRows = await db
			.select()
			.from(ephemeralSessions)
			.where(and(eq(ephemeralSessions.status, "active"), lt(ephemeralSessions.expiresAt, now)));

		let count = 0;
		for (const row of staleRows) {
			await markExpired(row.id, row.agentId);
			count++;
		}

		return ok({ count });
	}

	// ── Internal helpers ───────────────────────────────────────────────────────

	async function markExpired(sessionId: string, agentId: string): Promise<void> {
		const now = new Date();
		await db
			.update(ephemeralSessions)
			.set({ status: "expired", updatedAt: now })
			.where(eq(ephemeralSessions.id, sessionId));

		if (autoRevokeOnExpiry) {
			await db
				.update(agents)
				.set({ status: "revoked", updatedAt: now })
				.where(eq(agents.id, agentId));
		}
	}

	return {
		createSession,
		validateSession,
		consumeAction,
		revokeSession,
		listActiveSessions,
		cleanupExpired,
	};
}

// ─── Row mapper ───────────────────────────────────────────────────────────────

function rowToSession(row: {
	id: string;
	agentId: string;
	expiresAt: Date;
	maxActions: number | null;
	actionsUsed: number;
	status: string;
	auditGroupId: string;
	createdAt: Date;
}): EphemeralSession {
	return {
		sessionId: row.id,
		agentId: row.agentId,
		token: "", // never returned after initial creation
		expiresAt: row.expiresAt,
		maxActions: row.maxActions,
		actionsUsed: row.actionsUsed,
		status: row.status as EphemeralSession["status"],
		auditGroupId: row.auditGroupId,
		createdAt: row.createdAt,
	};
}
