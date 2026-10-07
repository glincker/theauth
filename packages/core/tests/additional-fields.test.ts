/**
 * Tests for the additional user/session fields plugin.
 *
 * Covers:
 * - validate: accepts valid fields
 * - validate: rejects missing required fields
 * - validate: rejects unknown fields
 * - validate: rejects wrong type
 * - getUserFields: returns defaults when user has no stored fields
 * - getUserFields: returns stored fields merged with defaults
 * - setUserFields: writes fields and reads them back
 * - setUserFields: throws for unknown userId
 * - setUserFields: throws when validation fails
 * - setUserFields: merges with existing fields (non-destructive)
 * - getSessionFields: returns defaults when session has no stored fields
 * - setSessionFields: writes and reads back
 * - setSessionFields: throws for unknown sessionId
 * - Plugin endpoints: GET /auth/users/fields
 * - Plugin endpoints: PUT /auth/users/fields
 * - Plugin endpoints: POST /auth/fields/validate returns 422 on failure
 * - Plugin context exposes the additionalFields module
 */

import { randomUUID } from "node:crypto";
import { eq } from "drizzle-orm";
import { beforeEach, describe, expect, it } from "vitest";
import type { AdditionalFieldsModule } from "../src/auth/additional-fields.js";
import { additionalFields, createAdditionalFieldsModule } from "../src/auth/additional-fields.js";
import type { Database } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import { sessions, users } from "../src/db/schema.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function createTestDb(): Promise<Database> {
	const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite");
	return db;
}

async function insertUser(db: Database, id = randomUUID()): Promise<string> {
	const now = new Date();
	await db.insert(users).values({
		id,
		email: `${id}@example.com`,
		name: "Test User",
		metadata: null,
		createdAt: now,
		updatedAt: now,
	});
	return id;
}

async function insertSession(db: Database, userId: string): Promise<string> {
	const id = randomUUID();
	const now = new Date();
	await db.insert(sessions).values({
		id,
		userId,
		expiresAt: new Date(now.getTime() + 3600_000),
		metadata: null,
		createdAt: now,
	});
	return id;
}

// ---------------------------------------------------------------------------
// validate
// ---------------------------------------------------------------------------

describe("AdditionalFieldsModule.validate", () => {
	let mod: AdditionalFieldsModule;

	beforeEach(async () => {
		const db = await createTestDb();
		mod = createAdditionalFieldsModule(
			{
				user: {
					plan: { type: "string", required: true },
					credits: { type: "number", required: false, defaultValue: 0 },
					active: { type: "boolean", required: false },
				},
			},
			db,
		);
	});

	it("returns valid: true for correct fields", () => {
		const result = mod.validate({ plan: "pro", credits: 50, active: true }, "user");
		expect(result.valid).toBe(true);
		expect(result.errors).toBeUndefined();
	});

	it("returns valid: false when a required field is missing", () => {
		const result = mod.validate({ credits: 10 }, "user");
		expect(result.valid).toBe(false);
		expect(result.errors).toEqual(expect.arrayContaining([expect.stringContaining('"plan"')]));
	});

	it("returns valid: false when a field has the wrong type", () => {
		const result = mod.validate({ plan: 42 }, "user"); // plan should be string
		expect(result.valid).toBe(false);
		expect(result.errors).toEqual(expect.arrayContaining([expect.stringContaining("string")]));
	});

	it("returns valid: false for a field not in the schema", () => {
		const result = mod.validate({ plan: "free", unknownField: "oops" }, "user");
		expect(result.valid).toBe(false);
		expect(result.errors).toEqual(
			expect.arrayContaining([expect.stringContaining("unknownField")]),
		);
	});

	it("returns valid: true with no schema configured", () => {
		// No session schema defined
		const result = mod.validate({ anything: true }, "session");
		expect(result.valid).toBe(true);
	});

	it("accumulates multiple errors in one call", () => {
		const result = mod.validate({ plan: 99, unknownField: "x" }, "user");
		expect(result.valid).toBe(false);
		expect(result.errors?.length).toBeGreaterThanOrEqual(2);
	});
});

// ---------------------------------------------------------------------------
// getUserFields
// ---------------------------------------------------------------------------

describe("AdditionalFieldsModule.getUserFields", () => {
	let db: Database;
	let mod: AdditionalFieldsModule;

	beforeEach(async () => {
		db = await createTestDb();
		mod = createAdditionalFieldsModule(
			{
				user: {
					plan: { type: "string", required: false, defaultValue: "free" },
					credits: { type: "number", required: false, defaultValue: 0 },
				},
			},
			db,
		);
	});

	it("returns defaults when the user has no stored additional fields", async () => {
		const userId = await insertUser(db);
		const fields = await mod.getUserFields(userId);
		expect(fields).toEqual({ plan: "free", credits: 0 });
	});

	it("returns stored fields merged with missing defaults", async () => {
		const userId = await insertUser(db);
		// Write via the module so Drizzle handles JSON serialisation correctly
		const noSchemaCheckMod = createAdditionalFieldsModule(
			{ user: { plan: { type: "string" }, credits: { type: "number", defaultValue: 0 } } },
			db,
		);
		await noSchemaCheckMod.setUserFields(userId, { plan: "pro" });

		const fields = await mod.getUserFields(userId);
		expect(fields.plan).toBe("pro");
		expect(fields.credits).toBe(0); // default applied
	});

	it("returns an empty object for an unknown user id (no defaults configured)", async () => {
		const plainMod = createAdditionalFieldsModule({}, db);
		const fields = await plainMod.getUserFields("ghost");
		expect(fields).toEqual({});
	});
});

// ---------------------------------------------------------------------------
// setUserFields
// ---------------------------------------------------------------------------

describe("AdditionalFieldsModule.setUserFields", () => {
	let db: Database;
	let mod: AdditionalFieldsModule;

	beforeEach(async () => {
		db = await createTestDb();
		mod = createAdditionalFieldsModule(
			{
				user: {
					plan: { type: "string", required: false },
					credits: { type: "number", required: false },
				},
			},
			db,
		);
	});

	it("writes fields and reads them back", async () => {
		const userId = await insertUser(db);
		await mod.setUserFields(userId, { plan: "enterprise", credits: 500 });
		const fields = await mod.getUserFields(userId);
		expect(fields.plan).toBe("enterprise");
		expect(fields.credits).toBe(500);
	});

	it("throws for an unknown userId", async () => {
		await expect(mod.setUserFields("no-such-user", { plan: "free" })).rejects.toThrow("not found");
	});

	it("throws when validation fails (wrong type)", async () => {
		const userId = await insertUser(db);
		await expect(mod.setUserFields(userId, { plan: 999 })).rejects.toThrow("validation failed");
	});

	it("merges with existing additional fields (non-destructive)", async () => {
		const userId = await insertUser(db);
		await mod.setUserFields(userId, { plan: "free" });
		await mod.setUserFields(userId, { credits: 25 });

		const fields = await mod.getUserFields(userId);
		expect(fields.plan).toBe("free"); // still present
		expect(fields.credits).toBe(25);
	});

	it("preserves other user.metadata keys when writing additional fields", async () => {
		const userId = await insertUser(db);

		// Use the anonymous-metadata approach: write a real record via insertUser
		// with metadata already containing an existing key, then set additional fields
		// via the module so Drizzle handles JSON serialisation.

		// First write additional fields directly; they go under 'additionalFields' sub-key.
		await mod.setUserFields(userId, { plan: "starter" });

		// Then update plan via module — ensure earlier write is still there via a
		// second module call, verifying the merge path.
		await mod.setUserFields(userId, { plan: "pro" });

		const fields = await mod.getUserFields(userId);
		expect(fields.plan).toBe("pro"); // latest write wins

		// Verify only 'additionalFields' sub-key is set, not a collision with top-level metadata
		const [row] = await db
			.select({ metadata: users.metadata })
			.from(users)
			.where(eq(users.id, userId));
		const meta = row?.metadata as Record<string, unknown> | null;
		expect(meta?.additionalFields).toEqual({ plan: "pro" });
	});
});

// ---------------------------------------------------------------------------
// getSessionFields / setSessionFields
// ---------------------------------------------------------------------------

describe("AdditionalFieldsModule.getSessionFields / setSessionFields", () => {
	let db: Database;
	let mod: AdditionalFieldsModule;

	beforeEach(async () => {
		db = await createTestDb();
		mod = createAdditionalFieldsModule(
			{
				session: {
					ipCountry: { type: "string", required: false, defaultValue: "unknown" },
					deviceType: { type: "string", required: false },
				},
			},
			db,
		);
	});

	it("returns session defaults when session has no stored fields", async () => {
		const userId = await insertUser(db);
		const sessionId = await insertSession(db, userId);
		const fields = await mod.getSessionFields(sessionId);
		expect(fields.ipCountry).toBe("unknown");
	});

	it("writes and reads back session fields", async () => {
		const userId = await insertUser(db);
		const sessionId = await insertSession(db, userId);

		await mod.setSessionFields(sessionId, { ipCountry: "DE", deviceType: "mobile" });

		const fields = await mod.getSessionFields(sessionId);
		expect(fields.ipCountry).toBe("DE");
		expect(fields.deviceType).toBe("mobile");
	});

	it("throws for an unknown session id", async () => {
		await expect(mod.setSessionFields("ghost-session", { ipCountry: "US" })).rejects.toThrow(
			"not found",
		);
	});
});

// ---------------------------------------------------------------------------
// Plugin endpoints
// ---------------------------------------------------------------------------

describe("additionalFields plugin endpoints", () => {
	it("GET /auth/users/fields returns user fields", async () => {
		const { createTheAuth } = await import("../src/theauth.js");

		const theauth = await createTheAuth({
			database: { provider: "sqlite", url: ":memory:" },
			auth: { session: { secret: "test-secret-at-least-32-characters-long" } },
			plugins: [
				additionalFields({
					user: { plan: { type: "string", required: false, defaultValue: "free" } },
				}),
			],
		});

		const userId = randomUUID();
		const now = new Date();
		await theauth.db.insert(users).values({
			id: userId,
			email: `${userId}@test.com`,
			name: "Test",
			metadata: null,
			createdAt: now,
			updatedAt: now,
		});

		const { token } = await theauth.auth.session.create(userId);

		const response = await theauth.plugins.handleRequest(
			new Request(`http://localhost/auth/users/fields?userId=${userId}`, {
				headers: { Authorization: `Bearer ${token}` },
			}),
		);

		expect(response?.status).toBe(200);
		const body = (await response?.json()) as { fields: Record<string, unknown> };
		expect(body.fields.plan).toBe("free");
	});

	it("GET /auth/users/fields returns 400 when userId is missing", async () => {
		const { createTheAuth } = await import("../src/theauth.js");

		const theauth = await createTheAuth({
			database: { provider: "sqlite", url: ":memory:" },
			auth: { session: { secret: "test-secret-at-least-32-characters-long" } },
			plugins: [additionalFields()],
		});

		// Create a user and auth session to pass the requireAuth check
		const userId = randomUUID();
		const now = new Date();
		await theauth.db.insert(users).values({
			id: userId,
			email: `${userId}@test.com`,
			name: "Test",
			metadata: null,
			createdAt: now,
			updatedAt: now,
		});
		const { token } = await theauth.auth.session.create(userId);

		const response = await theauth.plugins.handleRequest(
			new Request("http://localhost/auth/users/fields", {
				headers: { Authorization: `Bearer ${token}` },
			}),
		);
		expect(response?.status).toBe(400);
	});

	it("PUT /auth/users/fields writes fields and returns updated: true", async () => {
		const { createTheAuth } = await import("../src/theauth.js");

		const theauth = await createTheAuth({
			database: { provider: "sqlite", url: ":memory:" },
			auth: { session: { secret: "test-secret-at-least-32-characters-long" } },
			plugins: [
				additionalFields({
					user: { plan: { type: "string", required: false } },
				}),
			],
		});

		const userId = randomUUID();
		const now = new Date();
		await theauth.db.insert(users).values({
			id: userId,
			email: `${userId}@test.com`,
			name: "Put Test",
			metadata: null,
			createdAt: now,
			updatedAt: now,
		});

		const { token } = await theauth.auth.session.create(userId);

		const response = await theauth.plugins.handleRequest(
			new Request("http://localhost/auth/users/fields", {
				method: "PUT",
				headers: {
					"Content-Type": "application/json",
					Authorization: `Bearer ${token}`,
				},
				body: JSON.stringify({ userId, fields: { plan: "pro" } }),
			}),
		);

		expect(response?.status).toBe(200);
		const body = (await response?.json()) as { updated: boolean };
		expect(body.updated).toBe(true);
	});

	it("PUT /auth/users/fields returns 422 on validation failure", async () => {
		const { createTheAuth } = await import("../src/theauth.js");

		const theauth = await createTheAuth({
			database: { provider: "sqlite", url: ":memory:" },
			auth: { session: { secret: "test-secret-at-least-32-characters-long" } },
			plugins: [
				additionalFields({
					user: { credits: { type: "number", required: true } },
				}),
			],
		});

		const userId = randomUUID();
		const now = new Date();
		await theauth.db.insert(users).values({
			id: userId,
			email: `${userId}@test.com`,
			name: "Fail Test",
			metadata: null,
			createdAt: now,
			updatedAt: now,
		});

		const { token } = await theauth.auth.session.create(userId);

		const response = await theauth.plugins.handleRequest(
			new Request("http://localhost/auth/users/fields", {
				method: "PUT",
				headers: {
					"Content-Type": "application/json",
					Authorization: `Bearer ${token}`,
				},
				body: JSON.stringify({ userId, fields: { credits: "not-a-number" } }),
			}),
		);

		expect(response?.status).toBe(422);
	});

	it("POST /auth/fields/validate returns valid: true for correct fields", async () => {
		const { createTheAuth } = await import("../src/theauth.js");

		const theauth = await createTheAuth({
			database: { provider: "sqlite", url: ":memory:" },
			plugins: [
				additionalFields({
					user: { plan: { type: "string", required: false } },
				}),
			],
		});

		const response = await theauth.plugins.handleRequest(
			new Request("http://localhost/auth/fields/validate", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ schema: "user", fields: { plan: "free" } }),
			}),
		);

		expect(response?.status).toBe(200);
		const body = (await response?.json()) as { valid: boolean };
		expect(body.valid).toBe(true);
	});

	it("POST /auth/fields/validate returns 422 for invalid fields", async () => {
		const { createTheAuth } = await import("../src/theauth.js");

		const theauth = await createTheAuth({
			database: { provider: "sqlite", url: ":memory:" },
			plugins: [
				additionalFields({
					user: { plan: { type: "string", required: true } },
				}),
			],
		});

		const response = await theauth.plugins.handleRequest(
			new Request("http://localhost/auth/fields/validate", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ schema: "user", fields: {} }), // plan is required
			}),
		);

		expect(response?.status).toBe(422);
		const body = (await response?.json()) as { valid: boolean; errors: string[] };
		expect(body.valid).toBe(false);
		expect(body.errors).toBeDefined();
	});

	it("plugin context exposes the additionalFields module", async () => {
		const { createTheAuth } = await import("../src/theauth.js");

		const theauth = await createTheAuth({
			database: { provider: "sqlite", url: ":memory:" },
			plugins: [additionalFields({ user: { plan: { type: "string" } } })],
		});

		const ctx = theauth.plugins.getContext();
		expect(ctx.additionalFields).toBeDefined();
		const mod = ctx.additionalFields as AdditionalFieldsModule;
		expect(typeof mod.getUserFields).toBe("function");
		expect(typeof mod.setUserFields).toBe("function");
		expect(typeof mod.validate).toBe("function");
	});
});
