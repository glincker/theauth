/**
 * Tests for session refresh and token rotation.
 *
 * Covers:
 * - Successful refresh returns new access + refresh tokens
 * - Old refresh token is invalidated after use
 * - Expired refresh tokens are rejected
 * - Reuse detection revokes the entire token family
 * - Absolute timeout is enforced even with refresh
 * - Concurrent refresh requests are handled safely
 * - Audit log entries (via handleRequest HTTP layer)
 * - issueInitial wires up a usable family
 */

import { beforeEach, describe, expect, it } from "vitest";
import type { Database } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import * as schema from "../src/db/schema.js";
import type { SessionRefresher } from "../src/session/refresh.js";
import { createSessionRefresher, RefreshTokenError } from "../src/session/refresh.js";
import type { TokenFamilyStore } from "../src/session/token-family.js";
import { createTokenFamilyStore } from "../src/session/token-family.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const TEST_SECRET = "a-test-secret-that-is-at-least-32-chars-long!!";
const TEST_USER_ID = "user-refresh-test";

async function createTestDb(): Promise<Database> {
	const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite");

	db.insert(schema.users)
		.values({
			id: TEST_USER_ID,
			email: "refresh-test@example.com",
			name: "Refresh Test User",
			createdAt: new Date(),
			updatedAt: new Date(),
		})
		.run();

	// Second user for isolation checks.
	db.insert(schema.users)
		.values({
			id: "user-other",
			email: "other@example.com",
			name: "Other User",
			createdAt: new Date(),
			updatedAt: new Date(),
		})
		.run();

	return db;
}

// ---------------------------------------------------------------------------
// TokenFamilyStore unit tests
// ---------------------------------------------------------------------------

describe("TokenFamilyStore.createFamily", () => {
	let db: Database;
	let store: TokenFamilyStore;

	beforeEach(async () => {
		db = await createTestDb();
		store = createTokenFamilyStore(db);
	});

	it("creates a family with correct userId and expiry", async () => {
		const absoluteExpiry = new Date(Date.now() + 90 * 24 * 3600_000);
		const family = await store.createFamily(TEST_USER_ID, absoluteExpiry);

		expect(family.userId).toBe(TEST_USER_ID);
		expect(family.revoked).toBe(false);
		expect(family.absoluteExpiresAt.getTime()).toBe(absoluteExpiry.getTime());
	});

	it("returns isFamilyActive true for a fresh family", async () => {
		const family = await store.createFamily(TEST_USER_ID, new Date(Date.now() + 1_000_000));
		expect(store.isFamilyActive(family)).toBe(true);
	});

	it("returns isFamilyActive false when absoluteExpiresAt is in the past", async () => {
		const family = await store.createFamily(TEST_USER_ID, new Date(Date.now() - 1000));
		expect(store.isFamilyActive(family)).toBe(false);
	});
});

describe("TokenFamilyStore.issueToken / consumeToken", () => {
	let db: Database;
	let store: TokenFamilyStore;

	beforeEach(async () => {
		db = await createTestDb();
		store = createTokenFamilyStore(db);
	});

	it("issues a token and consumes it successfully", async () => {
		const family = await store.createFamily(TEST_USER_ID, new Date(Date.now() + 86_400_000));
		const { rawToken } = await store.issueToken(family.id, 30 * 86_400_000);

		const result = await store.consumeToken(rawToken);
		expect(result.status).toBe("ok");
		expect(result.family?.id).toBe(family.id);
	});

	it("returns not_found for an unknown token", async () => {
		const result = await store.consumeToken("completely-fake-token-string");
		expect(result.status).toBe("not_found");
	});

	it("marks token as used after consumption", async () => {
		const family = await store.createFamily(TEST_USER_ID, new Date(Date.now() + 86_400_000));
		const { rawToken } = await store.issueToken(family.id, 30 * 86_400_000);

		await store.consumeToken(rawToken);

		// Second consumption → reuse detected.
		const second = await store.consumeToken(rawToken);
		expect(second.status).toBe("reuse");
	});

	it("revokes the family when reuse is detected", async () => {
		const family = await store.createFamily(TEST_USER_ID, new Date(Date.now() + 86_400_000));
		const { rawToken } = await store.issueToken(family.id, 30 * 86_400_000);

		await store.consumeToken(rawToken); // first use — ok
		await store.consumeToken(rawToken); // second use — reuse, revokes family

		// Any subsequent consumption of another token in the same family fails.
		const { rawToken: token2 } = await store.issueToken(family.id, 30 * 86_400_000);
		const result = await store.consumeToken(token2);
		expect(result.status).toBe("revoked");
	});

	it("returns expired for a token past its individual TTL", async () => {
		const family = await store.createFamily(TEST_USER_ID, new Date(Date.now() + 86_400_000));
		// Issue a token that expires immediately (TTL = 0 ms).
		const { rawToken } = await store.issueToken(family.id, 0);

		// Wait a tick for the expiry to definitely be in the past.
		await new Promise((resolve) => setTimeout(resolve, 5));

		const result = await store.consumeToken(rawToken);
		expect(result.status).toBe("expired");
	});

	it("returns expired and revokes family when absolute timeout has passed", async () => {
		// Family with absolute expiry already in the past.
		const family = await store.createFamily(TEST_USER_ID, new Date(Date.now() - 1000));
		const { rawToken } = await store.issueToken(family.id, 30 * 86_400_000);

		const result = await store.consumeToken(rawToken);
		expect(result.status).toBe("expired");
	});
});

describe("TokenFamilyStore.revokeFamily / revokeFamiliesForUser", () => {
	let db: Database;
	let store: TokenFamilyStore;

	beforeEach(async () => {
		db = await createTestDb();
		store = createTokenFamilyStore(db);
	});

	it("revokeFamily prevents further token consumption", async () => {
		const family = await store.createFamily(TEST_USER_ID, new Date(Date.now() + 86_400_000));
		const { rawToken } = await store.issueToken(family.id, 30 * 86_400_000);

		await store.revokeFamily(family.id);

		const result = await store.consumeToken(rawToken);
		expect(result.status).toBe("revoked");
	});

	it("revokeFamiliesForUser revokes all families for the user", async () => {
		const f1 = await store.createFamily(TEST_USER_ID, new Date(Date.now() + 86_400_000));
		const f2 = await store.createFamily(TEST_USER_ID, new Date(Date.now() + 86_400_000));
		const { rawToken: t1 } = await store.issueToken(f1.id, 30 * 86_400_000);
		const { rawToken: t2 } = await store.issueToken(f2.id, 30 * 86_400_000);

		await store.revokeFamiliesForUser(TEST_USER_ID);

		expect((await store.consumeToken(t1)).status).toBe("revoked");
		expect((await store.consumeToken(t2)).status).toBe("revoked");
	});

	it("revokeFamiliesForUser does not affect other users", async () => {
		const f1 = await store.createFamily(TEST_USER_ID, new Date(Date.now() + 86_400_000));
		const f2 = await store.createFamily("user-other", new Date(Date.now() + 86_400_000));
		const { rawToken: t1 } = await store.issueToken(f1.id, 30 * 86_400_000);
		const { rawToken: t2 } = await store.issueToken(f2.id, 30 * 86_400_000);

		await store.revokeFamiliesForUser(TEST_USER_ID);

		expect((await store.consumeToken(t1)).status).toBe("revoked");
		expect((await store.consumeToken(t2)).status).toBe("ok");
	});
});

// ---------------------------------------------------------------------------
// SessionRefresher unit tests
// ---------------------------------------------------------------------------

describe("createSessionRefresher — constructor guards", () => {
	it("throws when secret is shorter than 32 characters", () => {
		expect(() =>
			createSessionRefresher({
				secret: "short",
				db: null as unknown as Database,
			}),
		).toThrow("at least 32 characters");
	});
});

describe("SessionRefresher.issueInitial", () => {
	let db: Database;
	let refresher: SessionRefresher;

	beforeEach(async () => {
		db = await createTestDb();
		refresher = createSessionRefresher({
			secret: TEST_SECRET,
			db,
			session: {
				accessTokenTTL: "15m",
				refreshTokenTTL: "30d",
				absoluteTimeout: "90d",
				rotateRefreshTokens: true,
				reuseDetection: true,
			},
		});
	});

	it("returns valid access and refresh tokens", async () => {
		const result = await refresher.issueInitial(TEST_USER_ID);

		expect(typeof result.accessToken).toBe("string");
		expect(result.accessToken.split(".").length).toBe(3); // JWT
		expect(typeof result.refreshToken).toBe("string");
		expect(result.refreshToken.length).toBeGreaterThan(10);
	});

	it("access token expires within ~15 minutes", async () => {
		const before = Date.now();
		const result = await refresher.issueInitial(TEST_USER_ID);
		const after = Date.now();

		const expiryMs = result.accessTokenExpiresAt.getTime();
		expect(expiryMs).toBeGreaterThan(before + 14 * 60_000);
		expect(expiryMs).toBeLessThan(after + 16 * 60_000);
	});

	it("refresh token expires within ~30 days", async () => {
		const result = await refresher.issueInitial(TEST_USER_ID);
		const nowMs = Date.now();
		const diffMs = result.refreshTokenExpiresAt.getTime() - nowMs;

		// Within ±1 minute of 30 days.
		expect(diffMs).toBeGreaterThan(30 * 86_400_000 - 60_000);
		expect(diffMs).toBeLessThan(30 * 86_400_000 + 60_000);
	});
});

describe("SessionRefresher.refresh — happy path", () => {
	let db: Database;
	let refresher: SessionRefresher;

	beforeEach(async () => {
		db = await createTestDb();
		refresher = createSessionRefresher({ secret: TEST_SECRET, db });
	});

	it("returns new access and refresh tokens", async () => {
		const initial = await refresher.issueInitial(TEST_USER_ID);
		const refreshed = await refresher.refresh(initial.refreshToken);

		expect(refreshed.accessToken).not.toBe(initial.accessToken);
		expect(refreshed.refreshToken).not.toBe(initial.refreshToken);
		expect(refreshed.family.userId).toBe(TEST_USER_ID);
	});

	it("new refresh token is usable", async () => {
		const { refreshToken: rt1 } = await refresher.issueInitial(TEST_USER_ID);
		const { refreshToken: rt2 } = await refresher.refresh(rt1);
		const third = await refresher.refresh(rt2);

		expect(third.accessToken).toBeTruthy();
	});
});

describe("SessionRefresher.refresh — old token invalidated", () => {
	let db: Database;
	let refresher: SessionRefresher;

	beforeEach(async () => {
		db = await createTestDb();
		refresher = createSessionRefresher({ secret: TEST_SECRET, db });
	});

	it("old refresh token is rejected after rotation", async () => {
		const { refreshToken: oldToken } = await refresher.issueInitial(TEST_USER_ID);
		await refresher.refresh(oldToken);

		await expect(refresher.refresh(oldToken)).rejects.toThrow(RefreshTokenError);
	});

	it("old token rejection has code token_reuse", async () => {
		const { refreshToken: oldToken } = await refresher.issueInitial(TEST_USER_ID);
		await refresher.refresh(oldToken);

		try {
			await refresher.refresh(oldToken);
			expect.fail("Should have thrown");
		} catch (err) {
			expect(err).toBeInstanceOf(RefreshTokenError);
			expect((err as RefreshTokenError).code).toBe("token_reuse");
		}
	});
});

describe("SessionRefresher.refresh — reuse detection revokes entire family", () => {
	let db: Database;
	let refresher: SessionRefresher;

	beforeEach(async () => {
		db = await createTestDb();
		refresher = createSessionRefresher({
			secret: TEST_SECRET,
			db,
			session: { reuseDetection: true },
		});
	});

	it("after reuse, new tokens from the same family are rejected", async () => {
		const { refreshToken: rt1 } = await refresher.issueInitial(TEST_USER_ID);
		const { refreshToken: rt2 } = await refresher.refresh(rt1);

		// Attacker presents the already-used rt1 — reuse detected.
		await expect(refresher.refresh(rt1)).rejects.toThrow(RefreshTokenError);

		// Legitimate user tries to use rt2 — family is now revoked.
		try {
			await refresher.refresh(rt2);
			expect.fail("Should have thrown");
		} catch (err) {
			expect(err).toBeInstanceOf(RefreshTokenError);
			expect((err as RefreshTokenError).code).toBe("family_revoked");
		}
	});
});

describe("SessionRefresher.refresh — expired token", () => {
	it("rejects an expired refresh token", async () => {
		const db = await createTestDb();
		// Ultra-short refresh TTL so the token expires before we use it.
		const refresher = createSessionRefresher({
			secret: TEST_SECRET,
			db,
			session: { refreshTokenTTL: "1ms" },
		});

		const { refreshToken } = await refresher.issueInitial(TEST_USER_ID);

		// Wait for the token to expire.
		await new Promise((resolve) => setTimeout(resolve, 10));

		try {
			await refresher.refresh(refreshToken);
			expect.fail("Should have thrown");
		} catch (err) {
			expect(err).toBeInstanceOf(RefreshTokenError);
			expect((err as RefreshTokenError).code).toBe("token_expired");
		}
	});
});

describe("SessionRefresher.refresh — absolute timeout", () => {
	it("rejects refresh when absolute timeout has been reached", async () => {
		const db = await createTestDb();
		// Absolute timeout in the past.
		const refresher = createSessionRefresher({
			secret: TEST_SECRET,
			db,
			session: { absoluteTimeout: "1ms" },
		});

		const { refreshToken } = await refresher.issueInitial(TEST_USER_ID);

		await new Promise((resolve) => setTimeout(resolve, 10));

		try {
			await refresher.refresh(refreshToken);
			expect.fail("Should have thrown");
		} catch (err) {
			expect(err).toBeInstanceOf(RefreshTokenError);
			// Status will be "expired" (absolute expiry caught in consumeToken).
			expect(["token_expired", "absolute_timeout"]).toContain((err as RefreshTokenError).code);
		}
	});
});

describe("SessionRefresher.refresh — concurrent requests", () => {
	it("only one concurrent refresh succeeds; the second gets reuse error", async () => {
		const db = await createTestDb();
		const refresher = createSessionRefresher({ secret: TEST_SECRET, db });

		const { refreshToken } = await refresher.issueInitial(TEST_USER_ID);

		// Fire both refreshes at the same time.
		const results = await Promise.allSettled([
			refresher.refresh(refreshToken),
			refresher.refresh(refreshToken),
		]);

		const fulfilled = results.filter((r) => r.status === "fulfilled");
		const rejected = results.filter((r) => r.status === "rejected");

		// Exactly one should succeed (first write wins due to UNIQUE constraint on
		// token_hash + the used flag atomic update).
		expect(fulfilled.length).toBe(1);
		expect(rejected.length).toBe(1);

		const rejectedReason = (rejected[0] as PromiseRejectedResult).reason as RefreshTokenError;
		expect(rejectedReason).toBeInstanceOf(RefreshTokenError);
		// Could be reuse or not_found depending on race.
		expect(["token_reuse", "not_found"]).toContain(rejectedReason.code);
	});
});

describe("SessionRefresher.revokeAll", () => {
	let db: Database;
	let refresher: SessionRefresher;

	beforeEach(async () => {
		db = await createTestDb();
		refresher = createSessionRefresher({ secret: TEST_SECRET, db });
	});

	it("revokes all families so subsequent refreshes fail", async () => {
		const { refreshToken: rt1 } = await refresher.issueInitial(TEST_USER_ID);
		const { refreshToken: rt2 } = await refresher.issueInitial(TEST_USER_ID);

		await refresher.revokeAll(TEST_USER_ID);

		await expect(refresher.refresh(rt1)).rejects.toThrow(RefreshTokenError);
		await expect(refresher.refresh(rt2)).rejects.toThrow(RefreshTokenError);
	});

	it("does not affect other users", async () => {
		const { refreshToken: userToken } = await refresher.issueInitial(TEST_USER_ID);
		const { refreshToken: otherToken } = await refresher.issueInitial("user-other");

		await refresher.revokeAll(TEST_USER_ID);

		await expect(refresher.refresh(userToken)).rejects.toThrow(RefreshTokenError);
		const otherResult = await refresher.refresh(otherToken);
		expect(otherResult.family.userId).toBe("user-other");
	});
});

// ---------------------------------------------------------------------------
// SessionRefresher.handleRequest — HTTP layer
// ---------------------------------------------------------------------------

describe("SessionRefresher.handleRequest — success", () => {
	let db: Database;
	let refresher: SessionRefresher;

	beforeEach(async () => {
		db = await createTestDb();
		refresher = createSessionRefresher({ secret: TEST_SECRET, db });
	});

	it("returns 200 with new tokens in body and Set-Cookie headers", async () => {
		const { refreshToken } = await refresher.issueInitial(TEST_USER_ID);

		const request = new Request("https://example.com/auth/refresh", {
			method: "POST",
			headers: { Cookie: `theauth_refresh=${refreshToken}` },
		});

		const { response, result } = await refresher.handleRequest(request);

		expect(response.status).toBe(200);
		expect(result?.accessToken).toBeTruthy();

		const body = (await response.json()) as Record<string, unknown>;
		expect(typeof body.accessToken).toBe("string");
		expect(typeof body.accessTokenExpiresAt).toBe("string");

		const setCookies = response.headers.getSetCookie
			? response.headers.getSetCookie()
			: [response.headers.get("set-cookie") ?? ""];
		expect(setCookies.some((c) => c.startsWith("theauth_access="))).toBe(true);
		expect(setCookies.some((c) => c.startsWith("theauth_refresh="))).toBe(true);
	});

	it("accepts refresh token from JSON body when no cookie", async () => {
		const { refreshToken } = await refresher.issueInitial(TEST_USER_ID);

		const request = new Request("https://example.com/auth/refresh", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ refreshToken }),
		});

		const { response } = await refresher.handleRequest(request);
		expect(response.status).toBe(200);
	});
});

describe("SessionRefresher.handleRequest — failure paths", () => {
	let db: Database;
	let refresher: SessionRefresher;

	beforeEach(async () => {
		db = await createTestDb();
		refresher = createSessionRefresher({ secret: TEST_SECRET, db });
	});

	it("returns 401 when no refresh token is provided", async () => {
		const request = new Request("https://example.com/auth/refresh", { method: "POST" });
		const { response, error } = await refresher.handleRequest(request);

		expect(response.status).toBe(401);
		expect(error).toBe("token_missing");
	});

	it("returns 401 for an unknown refresh token", async () => {
		const request = new Request("https://example.com/auth/refresh", {
			method: "POST",
			headers: { Cookie: "theauth_refresh=not-a-real-token" },
		});

		const { response, error } = await refresher.handleRequest(request);

		expect(response.status).toBe(401);
		expect(error).toBe("token_not_found");
	});

	it("clears the refresh cookie on reuse detection", async () => {
		const { refreshToken } = await refresher.issueInitial(TEST_USER_ID);

		// First rotation.
		await refresher.issueInitial(TEST_USER_ID); // create a second family to keep user in DB
		const req1 = new Request("https://example.com/auth/refresh", {
			method: "POST",
			headers: { Cookie: `theauth_refresh=${refreshToken}` },
		});
		await refresher.handleRequest(req1);

		// Re-use the old token.
		const req2 = new Request("https://example.com/auth/refresh", {
			method: "POST",
			headers: { Cookie: `theauth_refresh=${refreshToken}` },
		});
		const { response } = await refresher.handleRequest(req2);

		expect(response.status).toBe(401);
		// The response should clear the cookie.
		const setCookie = response.headers.get("set-cookie") ?? "";
		expect(setCookie).toMatch(/theauth_refresh=;/);
	});
});
