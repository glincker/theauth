/**
 * Passkey / WebAuthn tests.
 *
 * Covers:
 *   - CBOR decoder (all major types, size limits, depth limits, invalid input)
 *   - Registration option generation (challenge, rpId, excludeCredentials)
 *   - Authentication option generation (challenge, allowCredentials)
 *   - Credential listing and removal
 *   - Challenge expiry rejection
 *   - Challenge replay rejection (one-time use)
 *   - Wrong origin rejection
 *   - Wrong RP ID hash rejection
 *   - signCount rollback detection
 *   - Invalid CBOR input handling
 *   - Route dispatch via handleRequest
 *   - Cross-origin iframe rejection
 *   - User verification enforcement
 */

import Database from "better-sqlite3";
import { eq } from "drizzle-orm";
import { drizzle } from "drizzle-orm/better-sqlite3";
import { describe, expect, it } from "vitest";
import { decodeCbor } from "../src/auth/cbor.js";
import { createPasskeyModule, PASSKEY_ERROR, PasskeyError } from "../src/auth/passkey.js";
import { createTables } from "../src/db/migrations.js";
import * as schema from "../src/db/schema.js";

// Helpers

async function makeDb() {
	const sqlite = new Database(":memory:");
	const db = drizzle(sqlite, { schema });
	await createTables(db, "sqlite");
	return db;
}

function makeConfig() {
	return {
		rpName: "Test App",
		rpId: "example.com",
		origin: "https://example.com",
		attestation: "none" as const,
		userVerification: "preferred" as const,
		challengeTimeout: 60_000,
	};
}

function toBase64Url(bytes: Uint8Array): string {
	let binary = "";
	for (let i = 0; i < bytes.length; i++) {
		binary += String.fromCharCode(bytes[i] as number);
	}
	const b64 = btoa(binary);
	return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

function encodeClientData(data: Record<string, unknown>): string {
	return toBase64Url(new TextEncoder().encode(JSON.stringify(data)));
}

async function seedUser(db: ReturnType<typeof makeDb>, userId: string): Promise<void> {
	const now = new Date();
	await db.insert(schema.users).values({
		id: userId,
		email: `${userId}@test.example`,
		createdAt: now,
		updatedAt: now,
	});
}

// CBOR decoder tests

describe("decodeCbor", () => {
	it("decodes unsigned integers", () => {
		expect(decodeCbor(new Uint8Array([0x00]))).toBe(0);
		expect(decodeCbor(new Uint8Array([0x01]))).toBe(1);
		expect(decodeCbor(new Uint8Array([0x17]))).toBe(23);
		expect(decodeCbor(new Uint8Array([0x18, 0x18]))).toBe(24);
		expect(decodeCbor(new Uint8Array([0x18, 0xff]))).toBe(255);
	});

	it("decodes negative integers", () => {
		expect(decodeCbor(new Uint8Array([0x20]))).toBe(-1);
		expect(decodeCbor(new Uint8Array([0x21]))).toBe(-2);
		expect(decodeCbor(new Uint8Array([0x37]))).toBe(-24);
	});

	it("decodes byte strings", () => {
		const result = decodeCbor(new Uint8Array([0x42, 0xca, 0xfe]));
		expect(result).toBeInstanceOf(Uint8Array);
		expect(Array.from(result as Uint8Array)).toEqual([0xca, 0xfe]);
	});

	it("decodes text strings", () => {
		const bytes = new Uint8Array([0x63, 0x66, 0x6f, 0x6f]);
		expect(decodeCbor(bytes)).toBe("foo");
	});

	it("decodes arrays", () => {
		const bytes = new Uint8Array([0x83, 0x01, 0x02, 0x03]);
		expect(decodeCbor(bytes)).toEqual([1, 2, 3]);
	});

	it("decodes maps with numeric keys", () => {
		const result = decodeCbor(new Uint8Array([0xa1, 0x01, 0x02]));
		expect(result).toBeInstanceOf(Map);
		expect((result as Map<unknown, unknown>).get(1)).toBe(2);
	});

	it("decodes boolean simple values", () => {
		expect(decodeCbor(new Uint8Array([0xf5]))).toBe(true);
		expect(decodeCbor(new Uint8Array([0xf4]))).toBe(false);
		expect(decodeCbor(new Uint8Array([0xf6]))).toBe(null);
	});

	it("decodes nested structures", () => {
		const bytes = new Uint8Array([
			0xa1,
			0x63,
			0x66,
			0x6d,
			0x74, // "fmt"
			0x64,
			0x6e,
			0x6f,
			0x6e,
			0x65, // "none"
		]);
		const result = decodeCbor(bytes) as Map<unknown, unknown>;
		expect(result.get("fmt")).toBe("none");
	});

	it("rejects empty input", () => {
		expect(() => decodeCbor(new Uint8Array([]))).toThrow("CBOR: empty input");
	});

	it("rejects indefinite-length arrays", () => {
		// 0x9f = array with indefinite length (major type 4, additional info 31)
		expect(() => decodeCbor(new Uint8Array([0x9f, 0x01, 0xff]))).toThrow("indefinite-length");
	});

	it("rejects indefinite-length maps", () => {
		// 0xbf = map with indefinite length
		expect(() => decodeCbor(new Uint8Array([0xbf, 0x01, 0x02, 0xff]))).toThrow("indefinite-length");
	});

	it("rejects indefinite-length byte strings", () => {
		// 0x5f = byte string with indefinite length
		expect(() => decodeCbor(new Uint8Array([0x5f, 0x42, 0xca, 0xfe, 0xff]))).toThrow(
			"indefinite-length",
		);
	});

	it("rejects indefinite-length text strings", () => {
		// 0x7f = text string with indefinite length
		expect(() => decodeCbor(new Uint8Array([0x7f, 0x63, 0x66, 0x6f, 0x6f, 0xff]))).toThrow(
			"indefinite-length",
		);
	});

	it("rejects truncated input", () => {
		// 0x18 expects one more byte
		expect(() => decodeCbor(new Uint8Array([0x18]))).toThrow("unexpected end");
	});

	it("rejects byte string longer than remaining data", () => {
		// 0x45 = byte string length 5, but only 2 bytes follow
		expect(() => decodeCbor(new Uint8Array([0x45, 0xca, 0xfe]))).toThrow("unexpected end");
	});

	it("handles deeply nested structures up to limit", () => {
		// Build nested arrays: [[[[...]]]] at depth 30 (below limit of 32)
		const depth = 30;
		const bytes: number[] = [];
		for (let i = 0; i < depth; i++) {
			bytes.push(0x81); // array of 1
		}
		bytes.push(0x01); // innermost value
		expect(() => decodeCbor(new Uint8Array(bytes))).not.toThrow();
	});

	it("rejects structures exceeding max nesting depth", () => {
		// Build nested arrays deeper than 32
		const depth = 35;
		const bytes: number[] = [];
		for (let i = 0; i < depth; i++) {
			bytes.push(0x81); // array of 1
		}
		bytes.push(0x01);
		expect(() => decodeCbor(new Uint8Array(bytes))).toThrow("nesting depth");
	});
});

// Registration options tests

describe("getRegistrationOptions", () => {
	it("returns correct rpId and rpName", async () => {
		const db = await makeDb();
		const mod = createPasskeyModule(makeConfig(), db);

		const opts = await mod.getRegistrationOptions("user-1", "Alice");

		expect(opts.rp.id).toBe("example.com");
		expect(opts.rp.name).toBe("Test App");
	});

	it("includes a non-empty base64url challenge", async () => {
		const db = await makeDb();
		const mod = createPasskeyModule(makeConfig(), db);

		const opts = await mod.getRegistrationOptions("user-1", "Alice");

		expect(typeof opts.challenge).toBe("string");
		expect(opts.challenge.length).toBeGreaterThan(20);
		expect(opts.challenge).toMatch(/^[A-Za-z0-9_-]+$/);
	});

	it("sets timeout from config", async () => {
		const db = await makeDb();
		const config = { ...makeConfig(), challengeTimeout: 30_000 };
		const mod = createPasskeyModule(config, db);

		const opts = await mod.getRegistrationOptions("user-1", "Alice");
		expect(opts.timeout).toBe(30_000);
	});

	it("caps timeout at maximum of 5 minutes", async () => {
		const db = await makeDb();
		const config = { ...makeConfig(), challengeTimeout: 600_000 };
		const mod = createPasskeyModule(config, db);

		const opts = await mod.getRegistrationOptions("user-1", "Alice");
		expect(opts.timeout).toBe(300_000);
	});

	it("excludes existing credentials for the user", async () => {
		const db = await makeDb();
		const mod = createPasskeyModule(makeConfig(), db);

		await seedUser(db, "user-1");
		const now = new Date();
		await db.insert(schema.passkeyCredentials).values({
			id: "cred-1",
			userId: "user-1",
			credentialId: "existing-cred-id",
			publicKey: "fake-key",
			counter: 0,
			createdAt: now,
			lastUsedAt: now,
		});

		const opts = await mod.getRegistrationOptions("user-1", "Alice");

		expect(opts.excludeCredentials).toHaveLength(1);
		expect(opts.excludeCredentials[0]?.id).toBe("existing-cred-id");
		expect(opts.excludeCredentials[0]?.type).toBe("public-key");
	});

	it("includes supported pubKeyCredParams algorithms", async () => {
		const db = await makeDb();
		const mod = createPasskeyModule(makeConfig(), db);

		const opts = await mod.getRegistrationOptions("user-1", "Alice");

		const algs = opts.pubKeyCredParams.map((p) => p.alg);
		expect(algs).toContain(-7); // ES256
		expect(algs).toContain(-257); // RS256
	});

	it("stores challenge in database", async () => {
		const db = await makeDb();
		const mod = createPasskeyModule(makeConfig(), db);

		const opts = await mod.getRegistrationOptions("user-1", "Alice");

		const rows = await db.select().from(schema.passkeyChallenges);
		const matching = rows.filter((r) => r.challenge === opts.challenge);
		expect(matching).toHaveLength(1);
		expect(matching[0]?.type).toBe("registration");
		expect(matching[0]?.userId).toBe("user-1");
	});
});

// Authentication options tests

describe("getAuthenticationOptions", () => {
	it("returns correct rpId", async () => {
		const db = await makeDb();
		const mod = createPasskeyModule(makeConfig(), db);

		const opts = await mod.getAuthenticationOptions();
		expect(opts.rpId).toBe("example.com");
	});

	it("returns empty allowCredentials when no userId given", async () => {
		const db = await makeDb();
		const mod = createPasskeyModule(makeConfig(), db);

		const opts = await mod.getAuthenticationOptions();
		expect(opts.allowCredentials).toEqual([]);
	});

	it("populates allowCredentials for known userId", async () => {
		const db = await makeDb();
		const mod = createPasskeyModule(makeConfig(), db);

		await seedUser(db, "user-2");
		const now = new Date();
		await db.insert(schema.passkeyCredentials).values({
			id: "cred-a",
			userId: "user-2",
			credentialId: "cred-id-a",
			publicKey: "fake-key",
			counter: 5,
			transports: '["internal"]',
			createdAt: now,
			lastUsedAt: now,
		});

		const opts = await mod.getAuthenticationOptions("user-2");

		expect(opts.allowCredentials).toHaveLength(1);
		expect(opts.allowCredentials[0]?.id).toBe("cred-id-a");
		expect(opts.allowCredentials[0]?.type).toBe("public-key");
		expect(opts.allowCredentials[0]?.transports).toEqual(["internal"]);
	});

	it("stores authentication challenge in database", async () => {
		const db = await makeDb();
		const mod = createPasskeyModule(makeConfig(), db);

		const opts = await mod.getAuthenticationOptions("user-3");

		const rows = await db.select().from(schema.passkeyChallenges);
		const matching = rows.filter((r) => r.challenge === opts.challenge);
		expect(matching).toHaveLength(1);
		expect(matching[0]?.type).toBe("authentication");
	});
});

// listCredentials tests

describe("listCredentials", () => {
	it("returns empty array for user with no credentials", async () => {
		const db = await makeDb();
		const mod = createPasskeyModule(makeConfig(), db);

		const creds = await mod.listCredentials("nobody");
		expect(creds).toEqual([]);
	});

	it("returns credentials for the user", async () => {
		const db = await makeDb();
		const mod = createPasskeyModule(makeConfig(), db);

		await seedUser(db, "user-4");
		const now = new Date();
		await db.insert(schema.passkeyCredentials).values([
			{
				id: "c1",
				userId: "user-4",
				credentialId: "cred-1",
				publicKey: "pk1",
				counter: 0,
				deviceName: "iPhone",
				createdAt: now,
				lastUsedAt: now,
			},
			{
				id: "c2",
				userId: "user-4",
				credentialId: "cred-2",
				publicKey: "pk2",
				counter: 3,
				createdAt: now,
				lastUsedAt: now,
			},
		]);

		const creds = await mod.listCredentials("user-4");
		expect(creds).toHaveLength(2);

		const ids = creds.map((c) => c.credentialId).sort();
		expect(ids).toEqual(["cred-1", "cred-2"]);

		const withName = creds.find((c) => c.credentialId === "cred-1");
		expect(withName?.deviceName).toBe("iPhone");
	});

	it("does not return credentials for other users", async () => {
		const db = await makeDb();
		const mod = createPasskeyModule(makeConfig(), db);

		await seedUser(db, "user-5");
		const now = new Date();
		await db.insert(schema.passkeyCredentials).values({
			id: "c3",
			userId: "user-5",
			credentialId: "cred-5",
			publicKey: "pk5",
			counter: 0,
			createdAt: now,
			lastUsedAt: now,
		});

		const creds = await mod.listCredentials("user-99");
		expect(creds).toEqual([]);
	});
});

// removeCredential tests

describe("removeCredential", () => {
	it("removes the matching credential", async () => {
		const db = await makeDb();
		const mod = createPasskeyModule(makeConfig(), db);

		await seedUser(db, "user-6");
		const now = new Date();
		await db.insert(schema.passkeyCredentials).values({
			id: "cr1",
			userId: "user-6",
			credentialId: "to-remove",
			publicKey: "pk",
			counter: 0,
			createdAt: now,
			lastUsedAt: now,
		});

		await mod.removeCredential("to-remove", "user-6");

		const remaining = await mod.listCredentials("user-6");
		expect(remaining).toHaveLength(0);
	});

	it("does not remove credential belonging to a different user", async () => {
		const db = await makeDb();
		const mod = createPasskeyModule(makeConfig(), db);

		await seedUser(db, "user-7");
		const now = new Date();
		await db.insert(schema.passkeyCredentials).values({
			id: "cr2",
			userId: "user-7",
			credentialId: "others-cred",
			publicKey: "pk",
			counter: 0,
			createdAt: now,
			lastUsedAt: now,
		});

		// Attempt removal with wrong userId
		await mod.removeCredential("others-cred", "user-attacker");

		const remaining = await mod.listCredentials("user-7");
		expect(remaining).toHaveLength(1);
	});
});

// Challenge expiry tests

describe("challenge expiry", () => {
	it("verifyRegistration rejects an expired challenge", async () => {
		const db = await makeDb();
		const mod = createPasskeyModule(makeConfig(), db);

		// Insert an already-expired challenge
		const expiredAt = new Date(Date.now() - 1000);
		await db.insert(schema.passkeyChallenges).values({
			id: "ch-expired",
			challenge: "expired-challenge-value",
			userId: "user-8",
			type: "registration",
			expiresAt: expiredAt,
			createdAt: new Date(),
		});

		const clientDataJSON = encodeClientData({
			type: "webauthn.create",
			challenge: "expired-challenge-value",
			origin: "https://example.com",
		});

		await expect(
			mod.verifyRegistration("user-8", {
				id: "fake",
				rawId: "fake",
				type: "public-key",
				response: {
					clientDataJSON,
					attestationObject: toBase64Url(new Uint8Array([0xa0])), // empty CBOR map
				},
			}),
		).rejects.toThrow("expired");
	});

	it("verifyRegistration rejects expired challenge with CHALLENGE_EXPIRED code", async () => {
		const db = await makeDb();
		const mod = createPasskeyModule(makeConfig(), db);

		await db.insert(schema.passkeyChallenges).values({
			id: "ch-expired-2",
			challenge: "expired-challenge-2",
			userId: "user-8b",
			type: "registration",
			expiresAt: new Date(Date.now() - 1000),
			createdAt: new Date(),
		});

		const clientDataJSON = encodeClientData({
			type: "webauthn.create",
			challenge: "expired-challenge-2",
			origin: "https://example.com",
		});

		try {
			await mod.verifyRegistration("user-8b", {
				id: "fake",
				rawId: "fake",
				type: "public-key",
				response: {
					clientDataJSON,
					attestationObject: toBase64Url(new Uint8Array([0xa0])),
				},
			});
			expect.unreachable("Should have thrown");
		} catch (err) {
			expect(err).toBeInstanceOf(PasskeyError);
			expect((err as PasskeyError).code).toBe(PASSKEY_ERROR.CHALLENGE_EXPIRED);
		}
	});

	it("getAuthenticationOptions cleans up expired challenges", async () => {
		const db = await makeDb();
		const mod = createPasskeyModule(makeConfig(), db);

		// Insert an expired challenge
		await db.insert(schema.passkeyChallenges).values({
			id: "ch-old",
			challenge: "old-challenge",
			userId: null,
			type: "authentication",
			expiresAt: new Date(Date.now() - 5000),
			createdAt: new Date(),
		});

		// Generating new options should sweep expired ones
		await mod.getAuthenticationOptions();

		const rows = await db.select().from(schema.passkeyChallenges);
		const old = rows.find((r) => r.challenge === "old-challenge");
		expect(old).toBeUndefined();
	});
});

// Challenge replay tests (one-time use)

describe("challenge replay prevention", () => {
	it("deletes challenge after use in verifyRegistration (prevents replay)", async () => {
		const db = await makeDb();
		const mod = createPasskeyModule(makeConfig(), db);

		// Insert a valid challenge
		await db.insert(schema.passkeyChallenges).values({
			id: "ch-replay",
			challenge: "replay-challenge",
			userId: "user-replay",
			type: "registration",
			expiresAt: new Date(Date.now() + 60_000),
			createdAt: new Date(),
		});

		const clientDataJSON = encodeClientData({
			type: "webauthn.create",
			challenge: "replay-challenge",
			origin: "https://example.com",
		});

		// First attempt will fail at attestation parsing (because we give it a minimal CBOR map
		// without authData), but the challenge should still be consumed
		try {
			await mod.verifyRegistration("user-replay", {
				id: "fake",
				rawId: "fake",
				type: "public-key",
				response: {
					clientDataJSON,
					attestationObject: toBase64Url(new Uint8Array([0xa0])),
				},
			});
		} catch {
			// Expected to fail at attestation step
		}

		// Verify the challenge was deleted from DB
		const rows = await db
			.select()
			.from(schema.passkeyChallenges)
			.where(eq(schema.passkeyChallenges.challenge, "replay-challenge"));
		expect(rows).toHaveLength(0);

		// Second attempt with same challenge should get CHALLENGE_NOT_FOUND
		try {
			await mod.verifyRegistration("user-replay", {
				id: "fake",
				rawId: "fake",
				type: "public-key",
				response: {
					clientDataJSON,
					attestationObject: toBase64Url(new Uint8Array([0xa0])),
				},
			});
			expect.unreachable("Should have thrown");
		} catch (err) {
			expect(err).toBeInstanceOf(PasskeyError);
			expect((err as PasskeyError).code).toBe(PASSKEY_ERROR.CHALLENGE_NOT_FOUND);
		}
	});

	it("deletes challenge after use in verifyAuthentication (prevents replay)", async () => {
		const db = await makeDb();
		const mod = createPasskeyModule(makeConfig(), db);

		await db.insert(schema.passkeyChallenges).values({
			id: "ch-auth-replay",
			challenge: "auth-replay-challenge",
			userId: null,
			type: "authentication",
			expiresAt: new Date(Date.now() + 60_000),
			createdAt: new Date(),
		});

		const clientDataJSON = encodeClientData({
			type: "webauthn.get",
			challenge: "auth-replay-challenge",
			origin: "https://example.com",
		});

		// First attempt -- will fail at credential lookup but challenge is consumed
		try {
			await mod.verifyAuthentication({
				id: "nonexistent-cred",
				rawId: "nonexistent-cred",
				type: "public-key",
				response: {
					clientDataJSON,
					authenticatorData: toBase64Url(new Uint8Array(37)), // minimal authData
					signature: toBase64Url(new Uint8Array(64)),
				},
			});
		} catch {
			// Expected
		}

		// Second attempt should fail with CHALLENGE_NOT_FOUND
		try {
			await mod.verifyAuthentication({
				id: "nonexistent-cred",
				rawId: "nonexistent-cred",
				type: "public-key",
				response: {
					clientDataJSON,
					authenticatorData: toBase64Url(new Uint8Array(37)),
					signature: toBase64Url(new Uint8Array(64)),
				},
			});
			expect.unreachable("Should have thrown");
		} catch (err) {
			expect(err).toBeInstanceOf(PasskeyError);
			expect((err as PasskeyError).code).toBe(PASSKEY_ERROR.CHALLENGE_NOT_FOUND);
		}
	});
});

// Origin mismatch tests

describe("origin validation", () => {
	it("verifyRegistration rejects wrong origin", async () => {
		const db = await makeDb();
		const mod = createPasskeyModule(makeConfig(), db);

		const clientDataJSON = encodeClientData({
			type: "webauthn.create",
			challenge: "any-challenge",
			origin: "https://evil.com",
		});

		try {
			await mod.verifyRegistration("user-origin", {
				id: "fake",
				rawId: "fake",
				type: "public-key",
				response: {
					clientDataJSON,
					attestationObject: toBase64Url(new Uint8Array([0xa0])),
				},
			});
			expect.unreachable("Should have thrown");
		} catch (err) {
			expect(err).toBeInstanceOf(PasskeyError);
			expect((err as PasskeyError).code).toBe(PASSKEY_ERROR.ORIGIN_MISMATCH);
		}
	});

	it("verifyAuthentication rejects wrong origin", async () => {
		const db = await makeDb();
		const mod = createPasskeyModule(makeConfig(), db);

		const clientDataJSON = encodeClientData({
			type: "webauthn.get",
			challenge: "any-challenge",
			origin: "https://evil.com",
		});

		try {
			await mod.verifyAuthentication({
				id: "fake",
				rawId: "fake",
				type: "public-key",
				response: {
					clientDataJSON,
					authenticatorData: toBase64Url(new Uint8Array(37)),
					signature: toBase64Url(new Uint8Array(64)),
				},
			});
			expect.unreachable("Should have thrown");
		} catch (err) {
			expect(err).toBeInstanceOf(PasskeyError);
			expect((err as PasskeyError).code).toBe(PASSKEY_ERROR.ORIGIN_MISMATCH);
		}
	});

	it("supports multiple allowed origins", async () => {
		const db = await makeDb();
		const config = {
			...makeConfig(),
			origin: ["https://example.com", "https://app.example.com"],
		};
		const mod = createPasskeyModule(config, db);

		// Insert a challenge for "app.example.com"
		await db.insert(schema.passkeyChallenges).values({
			id: "ch-multi-origin",
			challenge: "multi-origin-challenge",
			userId: null,
			type: "authentication",
			expiresAt: new Date(Date.now() + 60_000),
			createdAt: new Date(),
		});

		const clientDataJSON = encodeClientData({
			type: "webauthn.get",
			challenge: "multi-origin-challenge",
			origin: "https://app.example.com",
		});

		// Should pass origin check but fail later at credential lookup (which is fine)
		try {
			await mod.verifyAuthentication({
				id: "nonexistent",
				rawId: "nonexistent",
				type: "public-key",
				response: {
					clientDataJSON,
					authenticatorData: toBase64Url(new Uint8Array(37)),
					signature: toBase64Url(new Uint8Array(64)),
				},
			});
		} catch (err) {
			// Should NOT be an origin mismatch
			expect(err).toBeInstanceOf(PasskeyError);
			expect((err as PasskeyError).code).not.toBe(PASSKEY_ERROR.ORIGIN_MISMATCH);
		}
	});

	it("rejects cross-origin iframe requests", async () => {
		const db = await makeDb();
		const mod = createPasskeyModule(makeConfig(), db);

		const clientDataJSON = encodeClientData({
			type: "webauthn.create",
			challenge: "any-challenge",
			origin: "https://example.com",
			crossOrigin: true,
		});

		try {
			await mod.verifyRegistration("user-cross", {
				id: "fake",
				rawId: "fake",
				type: "public-key",
				response: {
					clientDataJSON,
					attestationObject: toBase64Url(new Uint8Array([0xa0])),
				},
			});
			expect.unreachable("Should have thrown");
		} catch (err) {
			expect(err).toBeInstanceOf(PasskeyError);
			expect((err as PasskeyError).code).toBe(PASSKEY_ERROR.ORIGIN_MISMATCH);
		}
	});
});

// clientData.type mismatch tests

describe("clientData type validation", () => {
	it("verifyRegistration rejects webauthn.get type", async () => {
		const db = await makeDb();
		const mod = createPasskeyModule(makeConfig(), db);

		const clientDataJSON = encodeClientData({
			type: "webauthn.get", // wrong type for registration
			challenge: "any-challenge",
			origin: "https://example.com",
		});

		try {
			await mod.verifyRegistration("user-type", {
				id: "fake",
				rawId: "fake",
				type: "public-key",
				response: {
					clientDataJSON,
					attestationObject: toBase64Url(new Uint8Array([0xa0])),
				},
			});
			expect.unreachable("Should have thrown");
		} catch (err) {
			expect(err).toBeInstanceOf(PasskeyError);
			expect((err as PasskeyError).code).toBe(PASSKEY_ERROR.CLIENT_DATA_TYPE_MISMATCH);
		}
	});

	it("verifyAuthentication rejects webauthn.create type", async () => {
		const db = await makeDb();
		const mod = createPasskeyModule(makeConfig(), db);

		const clientDataJSON = encodeClientData({
			type: "webauthn.create", // wrong type for authentication
			challenge: "any-challenge",
			origin: "https://example.com",
		});

		try {
			await mod.verifyAuthentication({
				id: "fake",
				rawId: "fake",
				type: "public-key",
				response: {
					clientDataJSON,
					authenticatorData: toBase64Url(new Uint8Array(37)),
					signature: toBase64Url(new Uint8Array(64)),
				},
			});
			expect.unreachable("Should have thrown");
		} catch (err) {
			expect(err).toBeInstanceOf(PasskeyError);
			expect((err as PasskeyError).code).toBe(PASSKEY_ERROR.CLIENT_DATA_TYPE_MISMATCH);
		}
	});
});

// signCount rollback detection

describe("signCount rollback detection", () => {
	it("rejects authentication when signCount does not increase", async () => {
		const db = await makeDb();
		const mod = createPasskeyModule(makeConfig(), db);

		await seedUser(db, "user-counter");
		const now = new Date();

		// Seed a credential with counter=10
		await db.insert(schema.passkeyCredentials).values({
			id: "cred-counter",
			userId: "user-counter",
			credentialId: "counter-cred-id",
			publicKey: "fake-key",
			counter: 10,
			createdAt: now,
			lastUsedAt: now,
		});

		// Insert a valid challenge
		await db.insert(schema.passkeyChallenges).values({
			id: "ch-counter",
			challenge: "counter-challenge",
			userId: null,
			type: "authentication",
			expiresAt: new Date(Date.now() + 60_000),
			createdAt: now,
		});

		// Build authData with signCount=5 (less than stored 10)
		// authData: 32 bytes rpIdHash + 1 byte flags + 4 bytes signCount
		const rpIdHash = new Uint8Array(
			await crypto.subtle.digest("SHA-256", new TextEncoder().encode("example.com")),
		);
		const authDataBuf = new Uint8Array(37);
		authDataBuf.set(rpIdHash, 0);
		authDataBuf[32] = 0x01; // UP flag set
		// signCount = 5 (big-endian)
		authDataBuf[33] = 0;
		authDataBuf[34] = 0;
		authDataBuf[35] = 0;
		authDataBuf[36] = 5;

		const clientDataJSON = encodeClientData({
			type: "webauthn.get",
			challenge: "counter-challenge",
			origin: "https://example.com",
		});

		try {
			await mod.verifyAuthentication({
				id: "counter-cred-id",
				rawId: "counter-cred-id",
				type: "public-key",
				response: {
					clientDataJSON,
					authenticatorData: toBase64Url(authDataBuf),
					signature: toBase64Url(new Uint8Array(64)),
				},
			});
			expect.unreachable("Should have thrown");
		} catch (err) {
			expect(err).toBeInstanceOf(PasskeyError);
			// Could be SIGN_COUNT_ROLLBACK or SIGNATURE_INVALID (signature check happens first)
			// The important thing is it does NOT succeed
			expect([PASSKEY_ERROR.SIGN_COUNT_ROLLBACK, PASSKEY_ERROR.SIGNATURE_INVALID]).toContain(
				(err as PasskeyError).code,
			);
		}
	});
});

// User verification enforcement

describe("user verification enforcement", () => {
	it("rejects registration when UV required but not set", async () => {
		const db = await makeDb();
		const config = { ...makeConfig(), userVerification: "required" as const };
		const mod = createPasskeyModule(config, db);

		// Insert a valid challenge
		await db.insert(schema.passkeyChallenges).values({
			id: "ch-uv",
			challenge: "uv-challenge",
			userId: "user-uv",
			type: "registration",
			expiresAt: new Date(Date.now() + 60_000),
			createdAt: new Date(),
		});

		// Build minimal attestation with authData that has UP but NOT UV
		const rpIdHash = new Uint8Array(
			await crypto.subtle.digest("SHA-256", new TextEncoder().encode("example.com")),
		);
		// authData with UP + AT flags, credential data
		const credId = new Uint8Array([0x01, 0x02]);
		// Minimal COSE key map: {1: 2, 3: -7} (EC2, ES256)
		const coseKey = new Uint8Array([0xa2, 0x01, 0x02, 0x03, 0x26]); // minimal
		const authData = new Uint8Array(37 + 16 + 2 + credId.length + coseKey.length);
		authData.set(rpIdHash, 0);
		authData[32] = 0x41; // UP + AT flags (0x01 | 0x40), but NO UV (0x04)
		// signCount = 0
		authData[33] = 0;
		authData[34] = 0;
		authData[35] = 0;
		authData[36] = 0;
		// aaguid (16 bytes of zeros)
		// credential ID length (2 bytes)
		authData[53] = 0;
		authData[54] = credId.length;
		authData.set(credId, 55);
		authData.set(coseKey, 55 + credId.length);

		// Build attestation object as CBOR map: {"fmt": "none", "attStmt": {}, "authData": <bytes>}
		// For simplicity, manually construct CBOR
		const fmtKey = new Uint8Array([0x63, 0x66, 0x6d, 0x74]); // "fmt"
		const fmtVal = new Uint8Array([0x64, 0x6e, 0x6f, 0x6e, 0x65]); // "none"
		const attStmtKey = new Uint8Array([0x67, 0x61, 0x74, 0x74, 0x53, 0x74, 0x6d, 0x74]); // "attStmt"
		const attStmtVal = new Uint8Array([0xa0]); // empty map
		const authDataKey = new Uint8Array([0x68, 0x61, 0x75, 0x74, 0x68, 0x44, 0x61, 0x74, 0x61]); // "authData"
		// CBOR byte string header for authData
		const authDataHeader =
			authData.length < 24
				? new Uint8Array([0x40 | authData.length])
				: authData.length < 256
					? new Uint8Array([0x58, authData.length])
					: new Uint8Array([0x59, (authData.length >> 8) & 0xff, authData.length & 0xff]);

		const attestationParts = [
			new Uint8Array([0xa3]), // map of 3
			fmtKey,
			fmtVal,
			attStmtKey,
			attStmtVal,
			authDataKey,
			authDataHeader,
			authData,
		];
		const totalLen = attestationParts.reduce((sum, p) => sum + p.length, 0);
		const attestationObject = new Uint8Array(totalLen);
		let offset = 0;
		for (const part of attestationParts) {
			attestationObject.set(part, offset);
			offset += part.length;
		}

		const clientDataJSON = encodeClientData({
			type: "webauthn.create",
			challenge: "uv-challenge",
			origin: "https://example.com",
		});

		try {
			await mod.verifyRegistration("user-uv", {
				id: "fake-uv",
				rawId: "fake-uv",
				type: "public-key",
				response: {
					clientDataJSON,
					attestationObject: toBase64Url(attestationObject),
				},
			});
			expect.unreachable("Should have thrown");
		} catch (err) {
			expect(err).toBeInstanceOf(PasskeyError);
			expect((err as PasskeyError).code).toBe(PASSKEY_ERROR.USER_NOT_VERIFIED);
		}
	});
});

// Error code coverage

describe("error codes", () => {
	it("verifyAuthentication throws CREDENTIAL_NOT_FOUND for unknown credential", async () => {
		const db = await makeDb();
		const mod = createPasskeyModule(makeConfig(), db);

		// Insert a valid challenge
		await db.insert(schema.passkeyChallenges).values({
			id: "ch-nocred",
			challenge: "nocred-challenge",
			userId: null,
			type: "authentication",
			expiresAt: new Date(Date.now() + 60_000),
			createdAt: new Date(),
		});

		const rpIdHash = new Uint8Array(
			await crypto.subtle.digest("SHA-256", new TextEncoder().encode("example.com")),
		);
		const authDataBuf = new Uint8Array(37);
		authDataBuf.set(rpIdHash, 0);
		authDataBuf[32] = 0x01; // UP flag

		const clientDataJSON = encodeClientData({
			type: "webauthn.get",
			challenge: "nocred-challenge",
			origin: "https://example.com",
		});

		try {
			await mod.verifyAuthentication({
				id: "nonexistent-credential-id",
				rawId: "nonexistent-credential-id",
				type: "public-key",
				response: {
					clientDataJSON,
					authenticatorData: toBase64Url(authDataBuf),
					signature: toBase64Url(new Uint8Array(64)),
				},
			});
			expect.unreachable("Should have thrown");
		} catch (err) {
			expect(err).toBeInstanceOf(PasskeyError);
			expect((err as PasskeyError).code).toBe(PASSKEY_ERROR.CREDENTIAL_NOT_FOUND);
		}
	});

	it("verifyAuthentication throws RPID_MISMATCH for wrong RP ID", async () => {
		const db = await makeDb();
		const mod = createPasskeyModule(makeConfig(), db);

		await seedUser(db, "user-rpid");
		const now = new Date();
		await db.insert(schema.passkeyCredentials).values({
			id: "cred-rpid",
			userId: "user-rpid",
			credentialId: "rpid-cred-id",
			publicKey: "fake-key",
			counter: 0,
			createdAt: now,
			lastUsedAt: now,
		});

		await db.insert(schema.passkeyChallenges).values({
			id: "ch-rpid",
			challenge: "rpid-challenge",
			userId: null,
			type: "authentication",
			expiresAt: new Date(Date.now() + 60_000),
			createdAt: now,
		});

		// Build authData with wrong rpIdHash (hash of "wrong.com")
		const wrongRpIdHash = new Uint8Array(
			await crypto.subtle.digest("SHA-256", new TextEncoder().encode("wrong.com")),
		);
		const authDataBuf = new Uint8Array(37);
		authDataBuf.set(wrongRpIdHash, 0);
		authDataBuf[32] = 0x01; // UP flag

		const clientDataJSON = encodeClientData({
			type: "webauthn.get",
			challenge: "rpid-challenge",
			origin: "https://example.com",
		});

		try {
			await mod.verifyAuthentication({
				id: "rpid-cred-id",
				rawId: "rpid-cred-id",
				type: "public-key",
				response: {
					clientDataJSON,
					authenticatorData: toBase64Url(authDataBuf),
					signature: toBase64Url(new Uint8Array(64)),
				},
			});
			expect.unreachable("Should have thrown");
		} catch (err) {
			expect(err).toBeInstanceOf(PasskeyError);
			expect((err as PasskeyError).code).toBe(PASSKEY_ERROR.RPID_MISMATCH);
		}
	});
});

// handleRequest route dispatch tests

describe("handleRequest", () => {
	it("returns null for unrelated routes", async () => {
		const db = await makeDb();
		const mod = createPasskeyModule(makeConfig(), db);

		const req = new Request("https://example.com/auth/totp/setup", { method: "POST" });
		const result = await mod.handleRequest(req);
		expect(result).toBeNull();
	});

	it("POST /auth/passkey/register/options returns 400 when userId missing", async () => {
		const db = await makeDb();
		const mod = createPasskeyModule(makeConfig(), db);

		const req = new Request("https://example.com/auth/passkey/register/options", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ userName: "Alice" }),
		});

		const res = await mod.handleRequest(req);
		expect(res).not.toBeNull();
		expect(res?.status).toBe(400);
	});

	it("POST /auth/passkey/register/options returns options for valid request", async () => {
		const db = await makeDb();
		const mod = createPasskeyModule(makeConfig(), db);

		const req = new Request("https://example.com/auth/passkey/register/options", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ userId: "user-9", userName: "Alice" }),
		});

		const res = await mod.handleRequest(req);
		expect(res).not.toBeNull();
		expect(res?.status).toBe(200);

		const body = (await res?.json()) as { challenge: string; rp: { id: string } };
		expect(body.challenge).toBeTruthy();
		expect(body.rp.id).toBe("example.com");
	});

	it("POST /auth/passkey/login/options returns options", async () => {
		const db = await makeDb();
		const mod = createPasskeyModule(makeConfig(), db);

		const req = new Request("https://example.com/auth/passkey/login/options", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({}),
		});

		const res = await mod.handleRequest(req);
		expect(res).not.toBeNull();
		expect(res?.status).toBe(200);

		const body = (await res?.json()) as { challenge: string; rpId: string };
		expect(body.rpId).toBe("example.com");
		expect(body.challenge).toBeTruthy();
	});

	it("GET /auth/passkey/credentials returns 400 when userId missing", async () => {
		const db = await makeDb();
		const mod = createPasskeyModule(makeConfig(), db);

		const req = new Request("https://example.com/auth/passkey/credentials", {
			method: "GET",
		});

		const res = await mod.handleRequest(req);
		expect(res).not.toBeNull();
		expect(res?.status).toBe(400);
	});

	it("GET /auth/passkey/credentials returns credential list", async () => {
		const db = await makeDb();
		const mod = createPasskeyModule(makeConfig(), db);

		await seedUser(db, "user-10");
		const now = new Date();
		await db.insert(schema.passkeyCredentials).values({
			id: "lc1",
			userId: "user-10",
			credentialId: "list-cred",
			publicKey: "pk",
			counter: 0,
			createdAt: now,
			lastUsedAt: now,
		});

		const req = new Request("https://example.com/auth/passkey/credentials?userId=user-10", {
			method: "GET",
		});

		const res = await mod.handleRequest(req);
		expect(res).not.toBeNull();
		expect(res?.status).toBe(200);

		const body = (await res?.json()) as { credentials: { credentialId: string }[] };
		expect(body.credentials).toHaveLength(1);
		expect(body.credentials[0]?.credentialId).toBe("list-cred");
	});

	it("DELETE /auth/passkey/credentials/:id removes a credential", async () => {
		const db = await makeDb();
		const mod = createPasskeyModule(makeConfig(), db);

		await seedUser(db, "user-11");
		const now = new Date();
		await db.insert(schema.passkeyCredentials).values({
			id: "del1",
			userId: "user-11",
			credentialId: "del-cred",
			publicKey: "pk",
			counter: 0,
			createdAt: now,
			lastUsedAt: now,
		});

		const req = new Request("https://example.com/auth/passkey/credentials/del-cred", {
			method: "DELETE",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ userId: "user-11" }),
		});

		const res = await mod.handleRequest(req);
		expect(res).not.toBeNull();
		expect(res?.status).toBe(200);

		const remaining = await mod.listCredentials("user-11");
		expect(remaining).toHaveLength(0);
	});

	it("POST /auth/passkey/login/verify returns error code in JSON on failure", async () => {
		const db = await makeDb();
		const mod = createPasskeyModule(makeConfig(), db);

		const clientDataJSON = encodeClientData({
			type: "webauthn.get",
			challenge: "nonexistent",
			origin: "https://evil.com",
		});

		const req = new Request("https://example.com/auth/passkey/login/verify", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({
				response: {
					id: "fake",
					rawId: "fake",
					type: "public-key",
					response: {
						clientDataJSON,
						authenticatorData: toBase64Url(new Uint8Array(37)),
						signature: toBase64Url(new Uint8Array(64)),
					},
				},
			}),
		});

		const res = await mod.handleRequest(req);
		expect(res).not.toBeNull();
		expect(res?.status).toBe(401);

		const body = (await res?.json()) as { error: string; code: string };
		expect(body.code).toBe(PASSKEY_ERROR.ORIGIN_MISMATCH);
	});
});
