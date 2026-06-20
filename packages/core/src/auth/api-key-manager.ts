/**
 * API key management for TheAuth.
 *
 * Creates and validates static API keys with permission scopes. Keys are
 * stored as SHA-256 hashes — the full key is returned once at creation and
 * never stored. Validation tracks last-used time on every call.
 *
 * @example
 * ```typescript
 * const kavach = await createKavach({
 *   database: { provider: 'sqlite', url: 'kavach.db' },
 *   apiKeys: { prefix: 'kos_', defaultExpiryDays: 90 },
 * });
 *
 * const { key, apiKey } = await kavach.apiKeys.create({
 *   userId: 'user_abc',
 *   name: 'CI token',
 *   permissions: ['agents:read'],
 * });
 * // key = 'kos_a3f8c2e1...' — show once, store nowhere
 * ```
 */

import { eq } from "drizzle-orm";
import { generateId, randomBytesHex, sha256 } from "../crypto/web-crypto.js";
import type { Database } from "../db/database.js";
import { apiKeys as apiKeysTable } from "../db/schema.js";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface ApiKeyManagerConfig {
	/** Prefix for API keys (default: "kos_") */
	prefix?: string;
	/** Default expiry in days (default: 365) */
	defaultExpiryDays?: number;
}

export interface ApiKey {
	id: string;
	userId: string;
	name: string;
	prefix: string;
	permissions: string[];
	expiresAt: Date | null;
	lastUsedAt: Date | null;
	createdAt: Date;
}

export interface ApiKeyManagerModule {
	create: (input: {
		userId: string;
		name: string;
		permissions: string[];
		expiresAt?: Date;
	}) => Promise<{ apiKey: ApiKey; key: string }>;
	validate: (
		key: string,
	) => Promise<{ userId: string; permissions: string[]; keyId: string } | null>;
	/** Validate a key and check that it has the required permission */
	validateWithScope: (
		key: string,
		requiredPermission: string,
	) => Promise<{ userId: string; permissions: string[]; keyId: string } | null>;
	list: (userId: string) => Promise<ApiKey[]>;
	revoke: (keyId: string) => Promise<void>;
	rotate: (keyId: string) => Promise<{ apiKey: ApiKey; key: string }>;
	handleRequest: (request: Request) => Promise<Response | null>;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function hashKey(key: string): Promise<string> {
	return sha256(key);
}

// ---------------------------------------------------------------------------
// Row mapper
// ---------------------------------------------------------------------------

interface ApiKeyRow {
	id: string;
	userId: string;
	name: string;
	keyHash: string;
	keyPrefix: string;
	permissions: string[];
	expiresAt: Date | null;
	lastUsedAt: Date | null;
	createdAt: Date;
}

function rowToApiKey(row: ApiKeyRow): ApiKey {
	return {
		id: row.id,
		userId: row.userId,
		name: row.name,
		prefix: row.keyPrefix,
		permissions: row.permissions,
		expiresAt: row.expiresAt,
		lastUsedAt: row.lastUsedAt,
		createdAt: row.createdAt,
	};
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

export function createApiKeyManagerModule(
	config: ApiKeyManagerConfig,
	db: Database,
): ApiKeyManagerModule {
	const prefix = config.prefix ?? "kos_";
	const defaultExpiryDays = config.defaultExpiryDays ?? 365;

	function generateKey(): string {
		return `${prefix}${randomBytesHex(32)}`;
	}

	function computeDefaultExpiry(): Date {
		const d = new Date();
		d.setDate(d.getDate() + defaultExpiryDays);
		return d;
	}

	async function create(input: {
		userId: string;
		name: string;
		permissions: string[];
		expiresAt?: Date;
	}): Promise<{ apiKey: ApiKey; key: string }> {
		const key = generateKey();
		const keyHash = await hashKey(key);
		const keyPrefix = key.slice(0, prefix.length + 8); // prefix + first 8 hex chars
		const id = `key_${generateId().replace(/-/g, "")}`;
		const now = new Date();
		const expiresAt = input.expiresAt ?? computeDefaultExpiry();

		await db.insert(apiKeysTable).values({
			id,
			userId: input.userId,
			name: input.name,
			keyHash,
			keyPrefix,
			permissions: input.permissions,
			expiresAt,
			lastUsedAt: null,
			createdAt: now,
		});

		const apiKey: ApiKey = {
			id,
			userId: input.userId,
			name: input.name,
			prefix: keyPrefix,
			permissions: input.permissions,
			expiresAt,
			lastUsedAt: null,
			createdAt: now,
		};

		return { apiKey, key };
	}

	async function validate(
		key: string,
	): Promise<{ userId: string; permissions: string[]; keyId: string } | null> {
		const keyHash = await hashKey(key);
		const now = new Date();

		const rows = await db.select().from(apiKeysTable).where(eq(apiKeysTable.keyHash, keyHash));

		const row = rows[0] as ApiKeyRow | undefined;
		if (!row) return null;

		// Check expiry (null expiresAt = never expires)
		if (row.expiresAt !== null && row.expiresAt <= now) return null;

		// Update lastUsedAt (awaited to guarantee tracking)
		await db.update(apiKeysTable).set({ lastUsedAt: now }).where(eq(apiKeysTable.id, row.id));

		return {
			userId: row.userId,
			permissions: row.permissions,
			keyId: row.id,
		};
	}

	async function validateWithScope(
		key: string,
		requiredPermission: string,
	): Promise<{ userId: string; permissions: string[]; keyId: string } | null> {
		const result = await validate(key);
		if (!result) return null;

		// Wildcard permission grants access to everything
		if (result.permissions.includes("*")) return result;

		// Check the specific permission
		if (!result.permissions.includes(requiredPermission)) return null;

		return result;
	}

	async function list(userId: string): Promise<ApiKey[]> {
		const rows = (await db
			.select()
			.from(apiKeysTable)
			.where(eq(apiKeysTable.userId, userId))) as ApiKeyRow[];
		return rows.map(rowToApiKey);
	}

	async function revoke(keyId: string): Promise<void> {
		await db.delete(apiKeysTable).where(eq(apiKeysTable.id, keyId));
	}

	async function rotate(keyId: string): Promise<{ apiKey: ApiKey; key: string }> {
		const rows = (await db
			.select()
			.from(apiKeysTable)
			.where(eq(apiKeysTable.id, keyId))) as ApiKeyRow[];
		const existing = rows[0];
		if (!existing) throw new Error(`API key "${keyId}" not found`);

		// Revoke the old key
		await revoke(keyId);

		// Create a new key with the same config
		return create({
			userId: existing.userId,
			name: existing.name,
			permissions: existing.permissions,
			expiresAt: existing.expiresAt ?? undefined,
		});
	}

	// ── HTTP handler ──────────────────────────────────────────────────────────

	async function handleRequest(request: Request): Promise<Response | null> {
		const url = new URL(request.url);
		const { pathname } = url;
		const { method } = request;

		const json = (data: unknown, status = 200) =>
			new Response(JSON.stringify(data), {
				status,
				headers: { "Content-Type": "application/json" },
			});

		// POST /auth/api-keys
		if (method === "POST" && pathname === "/auth/api-keys") {
			let body: unknown;
			try {
				body = await request.json();
			} catch {
				return json({ error: "Invalid JSON body" }, 400);
			}
			const b = body as Record<string, unknown>;
			if (
				typeof b.userId !== "string" ||
				typeof b.name !== "string" ||
				!Array.isArray(b.permissions)
			) {
				return json({ error: "Missing required fields: userId, name, permissions" }, 400);
			}
			const expiresAt = b.expiresAt ? new Date(b.expiresAt as string) : undefined;
			const result = await create({
				userId: b.userId,
				name: b.name,
				permissions: b.permissions as string[],
				expiresAt,
			});
			return json(result, 201);
		}

		// GET /auth/api-keys/:userId
		const listMatch = /^\/auth\/api-keys\/([^/]+)$/.exec(pathname);
		if (method === "GET" && listMatch) {
			const userId = decodeURIComponent(listMatch[1] ?? "");
			const keys = await list(userId);
			return json(keys);
		}

		// DELETE /auth/api-keys/:keyId
		const deleteMatch = /^\/auth\/api-keys\/([^/]+)$/.exec(pathname);
		if (method === "DELETE" && deleteMatch) {
			const keyId = decodeURIComponent(deleteMatch[1] ?? "");
			await revoke(keyId);
			return json({ success: true });
		}

		// POST /auth/api-keys/:keyId/rotate
		const rotateMatch = /^\/auth\/api-keys\/([^/]+)\/rotate$/.exec(pathname);
		if (method === "POST" && rotateMatch) {
			const keyId = decodeURIComponent(rotateMatch[1] ?? "");
			try {
				const result = await rotate(keyId);
				return json(result);
			} catch (err) {
				return json({ error: err instanceof Error ? err.message : "Unknown error" }, 404);
			}
		}

		return null;
	}

	return {
		create,
		validate,
		validateWithScope,
		list,
		revoke,
		rotate,
		handleRequest,
	};
}
