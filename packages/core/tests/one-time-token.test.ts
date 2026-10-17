/** Tests for the one-time token module. */

import { createHash } from "node:crypto";
import { eq } from "drizzle-orm";
import { beforeEach, describe, expect, it } from "vitest";
import type { OneTimeTokenModule } from "../src/auth/one-time-token.js";
import { createOneTimeTokenModule } from "../src/auth/one-time-token.js";
import type { Database } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import { oneTimeTokens } from "../src/db/schema.js";

async function createTestDb(): Promise<Database> {
	const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite");
	return db;
}

function sha256(value: string): string {
	return createHash("sha256").update(value).digest("hex");
}

describe("OneTimeTokenModule.createToken", () => {
	let db: Database;
	let mod: OneTimeTokenModule;

	beforeEach(async () => {
		db = await createTestDb();
		mod = createOneTimeTokenModule({}, db);
	});

	it("succeeds for purpose email-verify", async () => {
		const result = await mod.createToken({
			purpose: "email-verify",
			identifier: "alice@example.com",
		});
		expect(result.success).toBe(true);
	});

	it("succeeds for purpose password-reset", async () => {
		const result = await mod.createToken({
			purpose: "password-reset",
			identifier: "bob@example.com",
		});
		expect(result.success).toBe(true);
	});

	it("succeeds for purpose invitation", async () => {
		const result = await mod.createToken({
			purpose: "invitation",
			identifier: "carol@example.com",
		});
		expect(result.success).toBe(true);
	});

	it("succeeds for purpose custom", async () => {
		const result = await mod.createToken({ purpose: "custom", identifier: "user-123" });
		expect(result.success).toBe(true);
	});

	it("returns a 64-char hex token", async () => {
		const result = await mod.createToken({
			purpose: "email-verify",
			identifier: "dave@example.com",
		});
		expect(result.success).toBe(true);
		if (!result.success) return;
		expect(result.data.token).toMatch(/^[0-9a-f]{64}$/);
	});

	it("returns expiresAt roughly equal to now + defaultTtl (3600s)", async () => {
		const before = Date.now();
		const result = await mod.createToken({
			purpose: "email-verify",
			identifier: "eve@example.com",
		});
		const after = Date.now();

		expect(result.success).toBe(true);
		if (!result.success) return;

		const expiresMs = result.data.expiresAt.getTime();
		expect(expiresMs).toBeGreaterThanOrEqual(before + 3599_000);
		expect(expiresMs).toBeLessThanOrEqual(after + 3601_000);
	});

	it("honours per-call ttlSeconds override", async () => {
		const before = Date.now();
		const result = await mod.createToken({
			purpose: "password-reset",
			identifier: "frank@example.com",
			ttlSeconds: 900,
		});
		const after = Date.now();

		expect(result.success).toBe(true);
		if (!result.success) return;

		const expiresMs = result.data.expiresAt.getTime();
		expect(expiresMs).toBeGreaterThanOrEqual(before + 899_000);
		expect(expiresMs).toBeLessThanOrEqual(after + 901_000);
	});

	it("honours module-level defaultTtlSeconds config", async () => {
		const customMod = createOneTimeTokenModule({ defaultTtlSeconds: 300 }, db);
		const before = Date.now();
		const result = await customMod.createToken({
			purpose: "email-verify",
			identifier: "grace@example.com",
		});
		const after = Date.now();

		expect(result.success).toBe(true);
		if (!result.success) return;

		const expiresMs = result.data.expiresAt.getTime();
		expect(expiresMs).toBeGreaterThanOrEqual(before + 299_000);
		expect(expiresMs).toBeLessThanOrEqual(after + 301_000);
	});

	it("stores the SHA-256 hash, not the raw token, in the database", async () => {
		const result = await mod.createToken({
			purpose: "invitation",
			identifier: "henry@example.com",
		});
		expect(result.success).toBe(true);
		if (!result.success) return;

		const rawToken = result.data.token;
		const rows = await db.select().from(oneTimeTokens).all();
		expect(rows).toHaveLength(1);

		const storedHash = rows[0]?.tokenHash;
		expect(storedHash).not.toBe(rawToken);
		expect(storedHash).toHaveLength(64); // SHA-256 hex
		expect(storedHash).toBe(sha256(rawToken));
	});

	it("preserves metadata in the database", async () => {
		const metadata = { orgId: "org-abc", role: "admin", invitedBy: "owner@example.com" };
		const result = await mod.createToken({
			purpose: "invitation",
			identifier: "iris@example.com",
			metadata,
		});

		expect(result.success).toBe(true);

		const rows = await db.select().from(oneTimeTokens).all();
		expect(rows[0]?.metadata).toEqual(metadata);
	});

	it("returns an error for an empty identifier", async () => {
		const result = await mod.createToken({ purpose: "custom", identifier: "" });
		expect(result.success).toBe(false);
		if (result.success) return;
		expect(result.error.code).toBe("INVALID_INPUT");
	});

	it("returns an error for an invalid purpose", async () => {
		const result = await mod.createToken({
			purpose: "unknown-purpose" as Parameters<typeof mod.createToken>[0]["purpose"],
			identifier: "jake@example.com",
		});
		expect(result.success).toBe(false);
		if (result.success) return;
		expect(result.error.code).toBe("INVALID_INPUT");
	});

	it("each call produces a unique token", async () => {
		const a = await mod.createToken({
			purpose: "email-verify",
			identifier: "kate@example.com",
		});
		const b = await mod.createToken({
			purpose: "email-verify",
			identifier: "kate@example.com",
		});

		expect(a.success).toBe(true);
		expect(b.success).toBe(true);
		if (!a.success || !b.success) return;

		expect(a.data.token).not.toBe(b.data.token);
	});
});

describe("OneTimeTokenModule.validateToken", () => {
	let db: Database;
	let mod: OneTimeTokenModule;

	beforeEach(async () => {
		db = await createTestDb();
		mod = createOneTimeTokenModule({}, db);
	});

	it("returns identifier and metadata on first valid use", async () => {
		const meta = { plan: "pro" };
		const create = await mod.createToken({
			purpose: "email-verify",
			identifier: "alice@example.com",
			metadata: meta,
		});
		expect(create.success).toBe(true);
		if (!create.success) return;

		const validate = await mod.validateToken(create.data.token, "email-verify");
		expect(validate.success).toBe(true);
		if (!validate.success) return;

		expect(validate.data.identifier).toBe("alice@example.com");
		expect(validate.data.metadata).toEqual(meta);
	});

	it("returns identifier without metadata field when none was stored", async () => {
		const create = await mod.createToken({
			purpose: "password-reset",
			identifier: "bob@example.com",
		});
		expect(create.success).toBe(true);
		if (!create.success) return;

		const validate = await mod.validateToken(create.data.token, "password-reset");
		expect(validate.success).toBe(true);
		if (!validate.success) return;

		expect(validate.data.identifier).toBe("bob@example.com");
		expect(validate.data.metadata).toBeUndefined();
	});

	it("marks the token as used in the database", async () => {
		const create = await mod.createToken({
			purpose: "email-verify",
			identifier: "carol@example.com",
		});
		expect(create.success).toBe(true);
		if (!create.success) return;

		await mod.validateToken(create.data.token, "email-verify");

		const rows = await db.select().from(oneTimeTokens).all();
		expect(rows[0]?.used).toBe(true);
	});

	it("fails on a second validation attempt (exactly-once)", async () => {
		const create = await mod.createToken({
			purpose: "invitation",
			identifier: "dave@example.com",
		});
		expect(create.success).toBe(true);
		if (!create.success) return;

		const first = await mod.validateToken(create.data.token, "invitation");
		expect(first.success).toBe(true);

		const second = await mod.validateToken(create.data.token, "invitation");
		expect(second.success).toBe(false);
		if (second.success) return;
		expect(second.error.code).toBe("TOKEN_ALREADY_USED");
	});

	it("fails for an unknown token", async () => {
		const result = await mod.validateToken("a".repeat(64), "email-verify");
		expect(result.success).toBe(false);
		if (result.success) return;
		expect(result.error.code).toBe("TOKEN_NOT_FOUND");
	});

	it("fails for an expired token", async () => {
		const create = await mod.createToken({
			purpose: "password-reset",
			identifier: "eve@example.com",
			ttlSeconds: 60,
		});
		expect(create.success).toBe(true);
		if (!create.success) return;

		// Back-date the expiry in the DB to simulate expiry without sleeping.
		await db
			.update(oneTimeTokens)
			.set({ expiresAt: new Date(Date.now() - 5_000) })
			.where(
				eq(oneTimeTokens.tokenHash, createHash("sha256").update(create.data.token).digest("hex")),
			);

		const validate = await mod.validateToken(create.data.token, "password-reset");
		expect(validate.success).toBe(false);
		if (validate.success) return;
		expect(validate.error.code).toBe("TOKEN_EXPIRED");
	});

	it("fails when purpose does not match", async () => {
		const create = await mod.createToken({
			purpose: "email-verify",
			identifier: "frank@example.com",
		});
		expect(create.success).toBe(true);
		if (!create.success) return;

		const validate = await mod.validateToken(create.data.token, "password-reset");
		expect(validate.success).toBe(false);
		if (validate.success) return;
		expect(validate.error.code).toBe("TOKEN_PURPOSE_MISMATCH");
	});

	it("the raw token is never stored in any database column", async () => {
		const create = await mod.createToken({
			purpose: "custom",
			identifier: "grace@example.com",
		});
		expect(create.success).toBe(true);
		if (!create.success) return;

		const rawToken = create.data.token;
		const rows = await db.select().from(oneTimeTokens).all();

		for (const row of rows) {
			expect(JSON.stringify(row)).not.toContain(rawToken);
		}
	});

	it("fails for an empty token string", async () => {
		const result = await mod.validateToken("", "email-verify");
		expect(result.success).toBe(false);
		if (result.success) return;
		expect(result.error.code).toBe("INVALID_INPUT");
	});

	it("fails for an empty purpose string", async () => {
		const result = await mod.validateToken("a".repeat(64), "");
		expect(result.success).toBe(false);
		if (result.success) return;
		expect(result.error.code).toBe("INVALID_INPUT");
	});
});

describe("OneTimeTokenModule.revokeTokens", () => {
	let db: Database;
	let mod: OneTimeTokenModule;

	beforeEach(async () => {
		db = await createTestDb();
		mod = createOneTimeTokenModule({}, db);
	});

	it("revokes all active tokens for an identifier and returns the count", async () => {
		await mod.createToken({ purpose: "email-verify", identifier: "alice@example.com" });
		await mod.createToken({ purpose: "password-reset", identifier: "alice@example.com" });

		const result = await mod.revokeTokens("alice@example.com");
		expect(result.success).toBe(true);
		if (!result.success) return;
		expect(result.data.count).toBe(2);

		const rows = await db.select().from(oneTimeTokens).all();
		expect(rows.every((r) => r.used)).toBe(true);
	});

	it("returns count = 0 when no active tokens exist for identifier", async () => {
		const result = await mod.revokeTokens("nobody@example.com");
		expect(result.success).toBe(true);
		if (!result.success) return;
		expect(result.data.count).toBe(0);
	});

	it("scopes revocation to a specific purpose, leaving other purposes intact", async () => {
		await mod.createToken({ purpose: "email-verify", identifier: "bob@example.com" });
		await mod.createToken({ purpose: "password-reset", identifier: "bob@example.com" });

		const result = await mod.revokeTokens("bob@example.com", "email-verify");
		expect(result.success).toBe(true);
		if (!result.success) return;
		expect(result.data.count).toBe(1);

		const rows = await db.select().from(oneTimeTokens).all();
		const usedRows = rows.filter((r) => r.used);
		const activeRows = rows.filter((r) => !r.used);

		expect(usedRows).toHaveLength(1);
		expect(usedRows[0]?.purpose).toBe("email-verify");
		expect(activeRows).toHaveLength(1);
		expect(activeRows[0]?.purpose).toBe("password-reset");
	});

	it("does not count already-used tokens toward the revoke result", async () => {
		const first = await mod.createToken({
			purpose: "invitation",
			identifier: "carol@example.com",
		});
		expect(first.success).toBe(true);
		if (!first.success) return;

		// Consume the first token.
		await mod.validateToken(first.data.token, "invitation");

		// Create a second active token.
		await mod.createToken({ purpose: "invitation", identifier: "carol@example.com" });

		const result = await mod.revokeTokens("carol@example.com", "invitation");
		expect(result.success).toBe(true);
		if (!result.success) return;
		// Only the second (still-active) token should be counted.
		expect(result.data.count).toBe(1);
	});

	it("does not revoke tokens belonging to a different identifier", async () => {
		await mod.createToken({ purpose: "email-verify", identifier: "dave@example.com" });
		await mod.createToken({ purpose: "email-verify", identifier: "eve@example.com" });

		const result = await mod.revokeTokens("dave@example.com");
		expect(result.success).toBe(true);
		if (!result.success) return;
		expect(result.data.count).toBe(1);

		const allRows = await db.select().from(oneTimeTokens).all();
		const eveRows = allRows.filter((r) => r.identifier === "eve@example.com");
		expect(eveRows).toHaveLength(1);
		expect(eveRows[0]?.used).toBe(false);
	});

	it("returns an error for an empty identifier", async () => {
		const result = await mod.revokeTokens("");
		expect(result.success).toBe(false);
		if (result.success) return;
		expect(result.error.code).toBe("INVALID_INPUT");
	});
});
