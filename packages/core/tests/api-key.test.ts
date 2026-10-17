/** Tests for API key management. */

import { beforeEach, describe, expect, it } from "vitest";
import type { ApiKeyManagerModule } from "../src/auth/api-key-manager.js";
import { createApiKeyManagerModule } from "../src/auth/api-key-manager.js";
import type { Database } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import { users } from "../src/db/schema.js";

async function createTestDb(): Promise<Database> {
	const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite");
	return db;
}

async function seedUser(db: Database, id: string, email: string): Promise<void> {
	const now = new Date();
	await db.insert(users).values({ id, email, name: null, createdAt: now, updatedAt: now });
}

const USER_ID = "user_key_test_001";
const PERMISSIONS = ["agents:read", "agents:write"];

describe("ApiKeyManagerModule.create", () => {
	let db: Database;
	let mod: ApiKeyManagerModule;

	beforeEach(async () => {
		db = await createTestDb();
		await seedUser(db, USER_ID, "test@example.com");
		mod = createApiKeyManagerModule({ prefix: "kos_", defaultExpiryDays: 365 }, db);
	});

	it("returns the full key string with the configured prefix", async () => {
		const { key } = await mod.create({
			userId: USER_ID,
			name: "CI token",
			permissions: PERMISSIONS,
		});
		expect(key).toMatch(/^kos_/);
	});

	it("full key is longer than just the prefix", async () => {
		const { key } = await mod.create({
			userId: USER_ID,
			name: "CI token",
			permissions: PERMISSIONS,
		});
		expect(key.length).toBeGreaterThan("kos_".length + 10);
	});

	it("apiKey.prefix is the display prefix (does not expose full key)", async () => {
		const { key, apiKey } = await mod.create({
			userId: USER_ID,
			name: "CI token",
			permissions: PERMISSIONS,
		});
		// The prefix stored on the record should be shorter than the full key
		expect(apiKey.prefix.length).toBeLessThan(key.length);
		// The prefix starts with the configured prefix string
		expect(apiKey.prefix).toMatch(/^kos_/);
	});

	it("applies default expiry when not specified", async () => {
		const { apiKey } = await mod.create({ userId: USER_ID, name: "Token", permissions: [] });
		expect(apiKey.expiresAt).toBeInstanceOf(Date);
		const daysAhead = (apiKey.expiresAt?.getTime() - Date.now()) / (1000 * 60 * 60 * 24);
		expect(daysAhead).toBeGreaterThan(360);
	});

	it("uses custom expiry when provided", async () => {
		const expiresAt = new Date(Date.now() + 10 * 86400 * 1000); // 10 days
		const { apiKey } = await mod.create({
			userId: USER_ID,
			name: "Token",
			permissions: [],
			expiresAt,
		});
		expect(apiKey.expiresAt?.getTime()).toBeCloseTo(expiresAt.getTime(), -3);
	});
});

describe("ApiKeyManagerModule.validate", () => {
	let db: Database;
	let mod: ApiKeyManagerModule;

	beforeEach(async () => {
		db = await createTestDb();
		await seedUser(db, USER_ID, "test@example.com");
		mod = createApiKeyManagerModule({ prefix: "kos_" }, db);
	});

	it("returns userId and permissions for a valid key", async () => {
		const { key } = await mod.create({ userId: USER_ID, name: "Token", permissions: PERMISSIONS });
		const result = await mod.validate(key);
		expect(result).not.toBeNull();
		expect(result?.userId).toBe(USER_ID);
		expect(result?.permissions).toEqual(PERMISSIONS);
		expect(result?.keyId).toMatch(/^key_/);
	});

	it("returns null for an incorrect key", async () => {
		await mod.create({ userId: USER_ID, name: "Token", permissions: PERMISSIONS });
		const result = await mod.validate("kos_wrongkeyvalue");
		expect(result).toBeNull();
	});

	it("returns null for a revoked key", async () => {
		const { key, apiKey } = await mod.create({
			userId: USER_ID,
			name: "Token",
			permissions: PERMISSIONS,
		});
		await mod.revoke(apiKey.id);
		const result = await mod.validate(key);
		expect(result).toBeNull();
	});

	it("returns null for an expired key", async () => {
		const expiresAt = new Date(Date.now() - 1000); // already expired
		const { key } = await mod.create({
			userId: USER_ID,
			name: "Token",
			permissions: PERMISSIONS,
			expiresAt,
		});
		const result = await mod.validate(key);
		expect(result).toBeNull();
	});
});

describe("ApiKeyManagerModule.list", () => {
	let db: Database;
	let mod: ApiKeyManagerModule;

	beforeEach(async () => {
		db = await createTestDb();
		await seedUser(db, USER_ID, "test@example.com");
		mod = createApiKeyManagerModule({ prefix: "kos_" }, db);
	});

	it("lists all keys for a user", async () => {
		await mod.create({ userId: USER_ID, name: "Token A", permissions: [] });
		await mod.create({ userId: USER_ID, name: "Token B", permissions: ["agents:read"] });
		const keys = await mod.list(USER_ID);
		expect(keys).toHaveLength(2);
	});

	it("listed keys have a prefix field but no full key", async () => {
		const { key } = await mod.create({ userId: USER_ID, name: "Token", permissions: [] });
		const keys = await mod.list(USER_ID);
		const k = keys[0];
		expect(k).toBeDefined();
		expect(k?.prefix).toBeTruthy();
		// prefix should be shorter than the full key
		expect(k?.prefix.length).toBeLessThan(key.length);
	});

	it("returns empty array for an unknown user", async () => {
		const keys = await mod.list("user_unknown_xyz");
		expect(keys).toHaveLength(0);
	});
});

describe("ApiKeyManagerModule.revoke", () => {
	let db: Database;
	let mod: ApiKeyManagerModule;

	beforeEach(async () => {
		db = await createTestDb();
		await seedUser(db, USER_ID, "test@example.com");
		mod = createApiKeyManagerModule({ prefix: "kos_" }, db);
	});

	it("removes the key from the list", async () => {
		const { apiKey } = await mod.create({ userId: USER_ID, name: "Token", permissions: [] });
		await mod.revoke(apiKey.id);
		const keys = await mod.list(USER_ID);
		expect(keys).toHaveLength(0);
	});
});

describe("ApiKeyManagerModule.rotate", () => {
	let db: Database;
	let mod: ApiKeyManagerModule;

	beforeEach(async () => {
		db = await createTestDb();
		await seedUser(db, USER_ID, "test@example.com");
		mod = createApiKeyManagerModule({ prefix: "kos_" }, db);
	});

	it("returns a new key with the same permissions", async () => {
		const { key: oldKey, apiKey: oldApiKey } = await mod.create({
			userId: USER_ID,
			name: "Token",
			permissions: PERMISSIONS,
		});
		const { key: newKey, apiKey: newApiKey } = await mod.rotate(oldApiKey.id);
		expect(newKey).not.toBe(oldKey);
		expect(newApiKey.permissions).toEqual(PERMISSIONS);
		expect(newApiKey.name).toBe("Token");
	});

	it("old key is invalidated after rotation", async () => {
		const { key: oldKey, apiKey } = await mod.create({
			userId: USER_ID,
			name: "Token",
			permissions: PERMISSIONS,
		});
		await mod.rotate(apiKey.id);
		const result = await mod.validate(oldKey);
		expect(result).toBeNull();
	});

	it("new key validates successfully", async () => {
		const { apiKey } = await mod.create({
			userId: USER_ID,
			name: "Token",
			permissions: PERMISSIONS,
		});
		const { key: newKey } = await mod.rotate(apiKey.id);
		const result = await mod.validate(newKey);
		expect(result).not.toBeNull();
		expect(result?.userId).toBe(USER_ID);
	});

	it("throws for a non-existent key ID", async () => {
		await expect(mod.rotate("key_nonexistent")).rejects.toThrow(/"key_nonexistent" not found/);
	});
});

describe("ApiKeyManagerModule.validateWithScope", () => {
	let db: Database;
	let mod: ApiKeyManagerModule;

	beforeEach(async () => {
		db = await createTestDb();
		await seedUser(db, USER_ID, "test@example.com");
		mod = createApiKeyManagerModule({ prefix: "kos_" }, db);
	});

	it("returns result when key has the required permission", async () => {
		const { key } = await mod.create({
			userId: USER_ID,
			name: "Scoped",
			permissions: ["agents:read", "agents:write"],
		});
		const result = await mod.validateWithScope(key, "agents:read");
		expect(result).not.toBeNull();
		expect(result?.userId).toBe(USER_ID);
	});

	it("returns null when key lacks the required permission", async () => {
		const { key } = await mod.create({
			userId: USER_ID,
			name: "Scoped",
			permissions: ["agents:read"],
		});
		const result = await mod.validateWithScope(key, "admin:delete");
		expect(result).toBeNull();
	});

	it("wildcard permission grants access to any scope", async () => {
		const { key } = await mod.create({
			userId: USER_ID,
			name: "Wildcard",
			permissions: ["*"],
		});
		const result = await mod.validateWithScope(key, "anything:here");
		expect(result).not.toBeNull();
	});

	it("returns null for an invalid key regardless of scope", async () => {
		const result = await mod.validateWithScope("kos_fakekeythatdoesnotexist", "agents:read");
		expect(result).toBeNull();
	});

	it("returns null for an expired key regardless of scope", async () => {
		const expiresAt = new Date(Date.now() - 1000);
		const { key } = await mod.create({
			userId: USER_ID,
			name: "Expired",
			permissions: ["agents:read"],
			expiresAt,
		});
		const result = await mod.validateWithScope(key, "agents:read");
		expect(result).toBeNull();
	});
});

describe("ApiKeyManagerModule.lastUsedAt tracking", () => {
	let db: Database;
	let mod: ApiKeyManagerModule;

	beforeEach(async () => {
		db = await createTestDb();
		await seedUser(db, USER_ID, "test@example.com");
		mod = createApiKeyManagerModule({ prefix: "kos_" }, db);
	});

	it("updates lastUsedAt on validate", async () => {
		const { key, apiKey } = await mod.create({
			userId: USER_ID,
			name: "Track",
			permissions: PERMISSIONS,
		});
		expect(apiKey.lastUsedAt).toBeNull();

		await mod.validate(key);

		const keys = await mod.list(USER_ID);
		const updated = keys.find((k) => k.id === apiKey.id);
		expect(updated?.lastUsedAt).toBeInstanceOf(Date);
	});
});

describe("ApiKeyManagerModule.key prefix format", () => {
	it("keys use the configured prefix", async () => {
		const db = await createTestDb();
		await seedUser(db, USER_ID, "test@example.com");
		const mod = createApiKeyManagerModule({ prefix: "kak_" }, db);
		const { key } = await mod.create({ userId: USER_ID, name: "Custom", permissions: [] });
		expect(key).toMatch(/^kak_/);
	});

	it("default prefix is kos_", async () => {
		const db = await createTestDb();
		await seedUser(db, USER_ID, "test@example.com");
		const mod = createApiKeyManagerModule({}, db);
		const { key } = await mod.create({ userId: USER_ID, name: "Default", permissions: [] });
		expect(key).toMatch(/^kos_/);
	});
});

describe("ApiKeyManagerModule.handleRequest", () => {
	let db: Database;
	let mod: ApiKeyManagerModule;

	beforeEach(async () => {
		db = await createTestDb();
		await seedUser(db, USER_ID, "test@example.com");
		mod = createApiKeyManagerModule({ prefix: "kos_" }, db);
	});

	it("POST /auth/api-keys creates a key and returns 201", async () => {
		const req = new Request("http://localhost/auth/api-keys", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ userId: USER_ID, name: "CI token", permissions: ["agents:read"] }),
		});
		const res = await mod.handleRequest(req);
		expect(res?.status).toBe(201);
		const body = await res?.json();
		expect(body.key).toMatch(/^kos_/);
		expect(body.apiKey.id).toMatch(/^key_/);
	});

	it("GET /auth/api-keys/:userId lists keys", async () => {
		await mod.create({ userId: USER_ID, name: "Token", permissions: [] });
		const req = new Request(`http://localhost/auth/api-keys/${USER_ID}`);
		const res = await mod.handleRequest(req);
		expect(res?.status).toBe(200);
		const body = await res?.json();
		expect(Array.isArray(body)).toBe(true);
		expect(body).toHaveLength(1);
	});

	it("POST /auth/api-keys/:keyId/rotate rotates the key", async () => {
		const { apiKey } = await mod.create({ userId: USER_ID, name: "Token", permissions: [] });
		const req = new Request(`http://localhost/auth/api-keys/${apiKey.id}/rotate`, {
			method: "POST",
		});
		const res = await mod.handleRequest(req);
		expect(res?.status).toBe(200);
		const body = await res?.json();
		expect(body.key).toMatch(/^kos_/);
	});

	it("returns null for unmatched paths", async () => {
		const req = new Request("http://localhost/other");
		const res = await mod.handleRequest(req);
		expect(res).toBeNull();
	});
});
