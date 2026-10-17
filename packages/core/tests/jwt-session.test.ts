/** Tests for the JWT session module. */

import { eq } from "drizzle-orm";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { JwtSessionModule } from "../src/auth/jwt-session.js";
import { createJwtSessionModule } from "../src/auth/jwt-session.js";
import type { Database } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import { jwtRefreshTokens, users } from "../src/db/schema.js";

const SAMPLE_USER = {
	id: "user-abc-123",
	email: "alice@example.com",
	name: "Alice",
};

async function createTestDb(): Promise<Database> {
	const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite");
	// Seed the user row that refresh tokens FK onto.
	const now = new Date();
	await db.insert(users).values({
		id: SAMPLE_USER.id,
		email: SAMPLE_USER.email,
		name: SAMPLE_USER.name,
		createdAt: now,
		updatedAt: now,
	});
	return db;
}

const TEST_SECRET = "super-secret-key-at-least-32-chars-long!!";

async function generateRsaKeyPair(): Promise<{ privateKey: CryptoKey; publicKey: CryptoKey }> {
	const pair = await crypto.subtle.generateKey(
		{
			name: "RSASSA-PKCS1-v1_5",
			modulusLength: 2048,
			publicExponent: new Uint8Array([1, 0, 1]),
			hash: "SHA-256",
		},
		true,
		["sign", "verify"],
	);
	return { privateKey: pair.privateKey, publicKey: pair.publicKey };
}

// createSession, HS256

describe("JwtSessionModule.createSession (HS256)", () => {
	let db: Database;
	let mod: JwtSessionModule;

	beforeEach(async () => {
		db = await createTestDb();
		mod = createJwtSessionModule({ secret: TEST_SECRET }, db);
	});

	it("succeeds and returns accessToken, refreshToken, expiresIn", async () => {
		const result = await mod.createSession(SAMPLE_USER);
		expect(result.success).toBe(true);
		if (!result.success) return;
		expect(typeof result.data.accessToken).toBe("string");
		expect(result.data.accessToken.length).toBeGreaterThan(20);
		expect(typeof result.data.refreshToken).toBe("string");
		expect(typeof result.data.expiresIn).toBe("number");
	});

	it("expiresIn matches accessTokenTtl config", async () => {
		const m = createJwtSessionModule({ secret: TEST_SECRET, accessTokenTtl: 300 }, db);
		const result = await m.createSession(SAMPLE_USER);
		expect(result.success).toBe(true);
		if (!result.success) return;
		expect(result.data.expiresIn).toBe(300);
	});

	it("access token is a three-part JWT", async () => {
		const result = await mod.createSession(SAMPLE_USER);
		expect(result.success).toBe(true);
		if (!result.success) return;
		expect(result.data.accessToken.split(".")).toHaveLength(3);
	});

	it("refresh token is a 64-char hex string", async () => {
		const result = await mod.createSession(SAMPLE_USER);
		expect(result.success).toBe(true);
		if (!result.success) return;
		expect(result.data.refreshToken).toMatch(/^[0-9a-f]{64}$/);
	});

	it("each call produces a unique refresh token", async () => {
		const r1 = await mod.createSession(SAMPLE_USER);
		const r2 = await mod.createSession(SAMPLE_USER);
		expect(r1.success && r2.success).toBe(true);
		if (!r1.success || !r2.success) return;
		expect(r1.data.refreshToken).not.toBe(r2.data.refreshToken);
	});

	it("rejects when user id is empty", async () => {
		const result = await mod.createSession({ id: "", email: "x@x.com" });
		expect(result.success).toBe(false);
		if (result.success) return;
		expect(result.error.code).toBe("INVALID_INPUT");
	});

	it("access token sub claim equals user id", async () => {
		const result = await mod.createSession(SAMPLE_USER);
		expect(result.success).toBe(true);
		if (!result.success) return;

		const verified = await mod.verifySession(result.data.accessToken);
		expect(verified.success).toBe(true);
		if (!verified.success) return;
		expect(verified.data.userId).toBe(SAMPLE_USER.id);
	});

	it("access token contains email and name when provided", async () => {
		const result = await mod.createSession(SAMPLE_USER);
		expect(result.success).toBe(true);
		if (!result.success) return;

		const verified = await mod.verifySession(result.data.accessToken);
		expect(verified.success).toBe(true);
		if (!verified.success) return;
		expect(verified.data.email).toBe(SAMPLE_USER.email);
		expect(verified.data.name).toBe(SAMPLE_USER.name);
	});

	it("custom claims appear in the access token payload", async () => {
		const m = createJwtSessionModule(
			{
				secret: TEST_SECRET,
				customClaims: () => ({ role: "admin", org: "acme" }),
			},
			db,
		);
		const result = await m.createSession(SAMPLE_USER);
		expect(result.success).toBe(true);
		if (!result.success) return;

		const verified = await m.verifySession(result.data.accessToken);
		expect(verified.success).toBe(true);
		if (!verified.success) return;
		expect(verified.data.claims.role).toBe("admin");
		expect(verified.data.claims.org).toBe("acme");
	});

	it("issuer claim is embedded when configured", async () => {
		const m = createJwtSessionModule(
			{ secret: TEST_SECRET, issuer: "https://myapp.example.com" },
			db,
		);
		const result = await m.createSession(SAMPLE_USER);
		expect(result.success).toBe(true);
		if (!result.success) return;

		const verified = await m.verifySession(result.data.accessToken);
		expect(verified.success).toBe(true);
		if (!verified.success) return;
		expect(verified.data.claims.iss).toBe("https://myapp.example.com");
	});

	it("audience claim is embedded when configured", async () => {
		const m = createJwtSessionModule({ secret: TEST_SECRET, audience: "myapp" }, db);
		const result = await m.createSession(SAMPLE_USER);
		expect(result.success).toBe(true);
		if (!result.success) return;

		const verified = await m.verifySession(result.data.accessToken);
		expect(verified.success).toBe(true);
		if (!verified.success) return;
		expect(verified.data.claims.aud).toBe("myapp");
	});
});

// createSession, RS256

describe("JwtSessionModule.createSession (RS256)", () => {
	let db: Database;

	beforeEach(async () => {
		db = await createTestDb();
	});

	it("succeeds with RS256 CryptoKey and verifies", async () => {
		const { privateKey, publicKey } = await generateRsaKeyPair();

		const signingMod = createJwtSessionModule({ secret: privateKey, algorithm: "RS256" }, db);
		const verifyMod = createJwtSessionModule({ secret: publicKey, algorithm: "RS256" }, db);

		const created = await signingMod.createSession(SAMPLE_USER);
		expect(created.success).toBe(true);
		if (!created.success) return;

		const verified = await verifyMod.verifySession(created.data.accessToken);
		expect(verified.success).toBe(true);
		if (!verified.success) return;
		expect(verified.data.userId).toBe(SAMPLE_USER.id);
	});
});

describe("JwtSessionModule.verifySession", () => {
	let db: Database;
	let mod: JwtSessionModule;

	beforeEach(async () => {
		db = await createTestDb();
		mod = createJwtSessionModule({ secret: TEST_SECRET }, db);
	});

	it("rejects empty token string", async () => {
		const result = await mod.verifySession("");
		expect(result.success).toBe(false);
		if (result.success) return;
		expect(result.error.code).toBe("INVALID_INPUT");
	});

	it("rejects a token signed with a different secret", async () => {
		const otherMod = createJwtSessionModule(
			{ secret: "different-secret-also-32-chars-long!!" },
			db,
		);
		const created = await otherMod.createSession(SAMPLE_USER);
		expect(created.success).toBe(true);
		if (!created.success) return;

		const result = await mod.verifySession(created.data.accessToken);
		expect(result.success).toBe(false);
	});

	it("rejects an expired token", async () => {
		// Issue a token with a 1-second TTL, then advance time past expiry.
		const m = createJwtSessionModule({ secret: TEST_SECRET, accessTokenTtl: 1 }, db);
		const created = await m.createSession(SAMPLE_USER);
		expect(created.success).toBe(true);
		if (!created.success) return;

		// Advance system time by 3 seconds so the token is definitely expired.
		vi.useFakeTimers();
		vi.setSystemTime(Date.now() + 3000);

		try {
			const result = await mod.verifySession(created.data.accessToken);
			expect(result.success).toBe(false);
			if (result.success) return;
			expect(result.error.code).toBe("TOKEN_EXPIRED");
		} finally {
			vi.useRealTimers();
		}
	});

	it("rejects a token with wrong issuer", async () => {
		const m = createJwtSessionModule(
			{ secret: TEST_SECRET, issuer: "https://other.example.com" },
			db,
		);
		const created = await m.createSession(SAMPLE_USER);
		expect(created.success).toBe(true);
		if (!created.success) return;

		const strictMod = createJwtSessionModule(
			{ secret: TEST_SECRET, issuer: "https://myapp.example.com" },
			db,
		);
		const result = await strictMod.verifySession(created.data.accessToken);
		expect(result.success).toBe(false);
	});

	it("rejects a token with wrong audience", async () => {
		const m = createJwtSessionModule({ secret: TEST_SECRET, audience: "other-audience" }, db);
		const created = await m.createSession(SAMPLE_USER);
		expect(created.success).toBe(true);
		if (!created.success) return;

		const strictMod = createJwtSessionModule(
			{ secret: TEST_SECRET, audience: "expected-audience" },
			db,
		);
		const result = await strictMod.verifySession(created.data.accessToken);
		expect(result.success).toBe(false);
	});

	it("custom claims round-trip correctly", async () => {
		const m = createJwtSessionModule(
			{
				secret: TEST_SECRET,
				customClaims: () => ({ permissions: ["read:posts", "write:posts"], tier: 2 }),
			},
			db,
		);
		const created = await m.createSession(SAMPLE_USER);
		expect(created.success).toBe(true);
		if (!created.success) return;

		const verified = await m.verifySession(created.data.accessToken);
		expect(verified.success).toBe(true);
		if (!verified.success) return;
		expect(verified.data.claims.permissions).toEqual(["read:posts", "write:posts"]);
		expect(verified.data.claims.tier).toBe(2);
	});
});

describe("JwtSessionModule.refreshSession", () => {
	let db: Database;
	let mod: JwtSessionModule;

	beforeEach(async () => {
		db = await createTestDb();
		mod = createJwtSessionModule({ secret: TEST_SECRET }, db);
	});

	it("returns a new token pair on a valid refresh token", async () => {
		const created = await mod.createSession(SAMPLE_USER);
		expect(created.success).toBe(true);
		if (!created.success) return;

		const refreshed = await mod.refreshSession(created.data.refreshToken);
		expect(refreshed.success).toBe(true);
		if (!refreshed.success) return;
		expect(typeof refreshed.data.accessToken).toBe("string");
		expect(typeof refreshed.data.refreshToken).toBe("string");
	});

	it("new refresh token differs from the old one (rotation)", async () => {
		const created = await mod.createSession(SAMPLE_USER);
		expect(created.success).toBe(true);
		if (!created.success) return;

		const refreshed = await mod.refreshSession(created.data.refreshToken);
		expect(refreshed.success).toBe(true);
		if (!refreshed.success) return;
		expect(refreshed.data.refreshToken).not.toBe(created.data.refreshToken);
	});

	it("old refresh token is marked used after refresh", async () => {
		const created = await mod.createSession(SAMPLE_USER);
		expect(created.success).toBe(true);
		if (!created.success) return;

		await mod.refreshSession(created.data.refreshToken);

		// Second refresh with old token should fail
		const second = await mod.refreshSession(created.data.refreshToken);
		expect(second.success).toBe(false);
		if (second.success) return;
		expect(second.error.code).toBe("REFRESH_TOKEN_USED");
	});

	it("new token pair is valid and verifiable", async () => {
		const created = await mod.createSession(SAMPLE_USER);
		expect(created.success).toBe(true);
		if (!created.success) return;

		const refreshed = await mod.refreshSession(created.data.refreshToken);
		expect(refreshed.success).toBe(true);
		if (!refreshed.success) return;

		const verified = await mod.verifySession(refreshed.data.accessToken);
		expect(verified.success).toBe(true);
		if (!verified.success) return;
		expect(verified.data.userId).toBe(SAMPLE_USER.id);
	});

	it("rejects an unknown refresh token", async () => {
		const result = await mod.refreshSession("a".repeat(64));
		expect(result.success).toBe(false);
		if (result.success) return;
		expect(result.error.code).toBe("REFRESH_TOKEN_NOT_FOUND");
	});

	it("rejects an expired refresh token", async () => {
		const m = createJwtSessionModule({ secret: TEST_SECRET, refreshTokenTtl: 1 }, db);
		const created = await m.createSession(SAMPLE_USER);
		expect(created.success).toBe(true);
		if (!created.success) return;

		// Manually expire the token by back-dating it in DB
		const rows = await db.select().from(jwtRefreshTokens).limit(1);
		if (rows[0]) {
			const pastDate = new Date(Date.now() - 5000);
			await db
				.update(jwtRefreshTokens)
				.set({ expiresAt: pastDate })
				.where(eq(jwtRefreshTokens.id, rows[0].id));
		}

		const result = await m.refreshSession(created.data.refreshToken);
		expect(result.success).toBe(false);
		if (result.success) return;
		expect(result.error.code).toBe("REFRESH_TOKEN_EXPIRED");
	});

	it("rejects empty string", async () => {
		const result = await mod.refreshSession("");
		expect(result.success).toBe(false);
		if (result.success) return;
		expect(result.error.code).toBe("INVALID_INPUT");
	});
});

describe("JwtSessionModule.revokeSession", () => {
	let db: Database;
	let mod: JwtSessionModule;

	beforeEach(async () => {
		db = await createTestDb();
		mod = createJwtSessionModule({ secret: TEST_SECRET }, db);
	});

	it("marks the refresh token as used", async () => {
		const created = await mod.createSession(SAMPLE_USER);
		expect(created.success).toBe(true);
		if (!created.success) return;

		const revoked = await mod.revokeSession(created.data.refreshToken);
		expect(revoked.success).toBe(true);

		const refreshed = await mod.refreshSession(created.data.refreshToken);
		expect(refreshed.success).toBe(false);
	});

	it("subsequent refresh fails after revocation", async () => {
		const created = await mod.createSession(SAMPLE_USER);
		expect(created.success).toBe(true);
		if (!created.success) return;

		await mod.revokeSession(created.data.refreshToken);

		const result = await mod.refreshSession(created.data.refreshToken);
		expect(result.success).toBe(false);
		if (result.success) return;
		expect(result.error.code).toBe("REFRESH_TOKEN_USED");
	});

	it("is idempotent when called twice", async () => {
		const created = await mod.createSession(SAMPLE_USER);
		expect(created.success).toBe(true);
		if (!created.success) return;

		const r1 = await mod.revokeSession(created.data.refreshToken);
		const r2 = await mod.revokeSession(created.data.refreshToken);
		expect(r1.success).toBe(true);
		expect(r2.success).toBe(true);
	});

	it("is idempotent for unknown token", async () => {
		const result = await mod.revokeSession("b".repeat(64));
		expect(result.success).toBe(true);
	});

	it("rejects empty string", async () => {
		const result = await mod.revokeSession("");
		expect(result.success).toBe(false);
		if (result.success) return;
		expect(result.error.code).toBe("INVALID_INPUT");
	});
});
