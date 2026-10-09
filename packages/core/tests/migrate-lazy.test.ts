import { describe, expect, it, vi } from "vitest";
import { pbkdf2Verify } from "../src/crypto/web-crypto.js";
import { bytesToBase64, encodeLegacyHash } from "../src/migrate/hash-format.js";
import { createLazyPasswordMigrator, verifyLegacyHash } from "../src/migrate/legacy-hash.js";
import { createMemoryMigrationStore } from "../src/migrate/memory-store.js";
import { scrypt } from "../src/migrate/scrypt.js";
import type { LegacyHash } from "../src/migrate/types.js";

const enc = new TextEncoder();

function hex(b: Uint8Array): string {
	return [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
}

async function pbkdf2(pw: string, salt: Uint8Array, iterations: number, hash: string, len: number) {
	const key = await crypto.subtle.importKey("raw", enc.encode(pw), "PBKDF2", false, ["deriveBits"]);
	return new Uint8Array(
		await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations, hash }, key, len * 8),
	);
}

describe("scrypt", () => {
	it("matches the RFC 7914 vector", async () => {
		const out = await scrypt(enc.encode(""), enc.encode(""), { N: 16, r: 1, p: 1, dkLen: 64 });
		expect(out && hex(out)).toBe(
			"77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906",
		);
	});
	it("refuses absurd parameters", async () => {
		expect(
			await scrypt(enc.encode("a"), enc.encode("b"), { N: 2 ** 24, r: 8, p: 1, dkLen: 32 }),
		).toBeNull();
		expect(
			await scrypt(enc.encode("a"), enc.encode("b"), { N: 15, r: 8, p: 1, dkLen: 32 }),
		).toBeNull();
	});
});

describe("verifyLegacyHash", () => {
	const salt = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
	for (const [algorithm, h] of [
		["pbkdf2-sha1", "SHA-1"],
		["pbkdf2-sha256", "SHA-256"],
		["pbkdf2-sha512", "SHA-512"],
	] as const) {
		it(`${algorithm} accepts the right password only`, async () => {
			const derived = await pbkdf2("hunter2-test", salt, 1000, h, 32);
			const legacy: LegacyHash = {
				algorithm,
				hash: bytesToBase64(derived),
				salt: bytesToBase64(salt),
				params: { iterations: 1000 },
			};
			expect(await verifyLegacyHash("hunter2-test", legacy)).toEqual({ success: true, data: true });
			expect(await verifyLegacyHash("wrong", legacy)).toEqual({ success: true, data: false });
		});
	}

	it("scrypt with the Better Auth layout (hex salt string, NFKC)", async () => {
		const saltHex = "00ff10";
		const key = await scrypt(enc.encode("pässword".normalize("NFKC")), enc.encode(saltHex), {
			N: 16,
			r: 2,
			p: 1,
			dkLen: 16,
		});
		const legacy: LegacyHash = {
			algorithm: "scrypt",
			hash: bytesToBase64(key as Uint8Array),
			salt: bytesToBase64(enc.encode(saltHex)),
			params: { N: 16, r: 2, p: 1, nfkc: true },
		};
		expect((await verifyLegacyHash("pässword", legacy)).success).toBe(true);
		expect(await verifyLegacyHash("pässword", legacy)).toEqual({ success: true, data: true });
		expect(await verifyLegacyHash("nope", legacy)).toEqual({ success: true, data: false });
	});

	it("bcrypt and argon2 are documented gaps unless a verifier is passed", async () => {
		const legacy: LegacyHash = { algorithm: "bcrypt", hash: "$2b$10$x" };
		const missing = await verifyLegacyHash("pw", legacy);
		expect(!missing.success && missing.error.code).toBe("VERIFIER_MISSING");
		const bcrypt = vi.fn(async (pw: string) => pw === "pw");
		expect(await verifyLegacyHash("pw", legacy, { bcrypt })).toEqual({ success: true, data: true });
		expect(await verifyLegacyHash("no", legacy, { bcrypt })).toEqual({
			success: true,
			data: false,
		});
	});

	it("rejects pbkdf2 with a missing salt or silly iteration count", async () => {
		const bad: LegacyHash = {
			algorithm: "pbkdf2-sha256",
			hash: "AAEC",
			params: { iterations: 10 },
		};
		expect(await verifyLegacyHash("x", bad)).toEqual({ success: true, data: false });
		const huge: LegacyHash = { ...bad, salt: "AAEC", params: { iterations: 2_000_000_000 } };
		expect(await verifyLegacyHash("x", huge)).toEqual({ success: true, data: false });
	});
});

describe("lazy migration", () => {
	async function setup() {
		const store = createMemoryMigrationStore();
		const user = await store.createUser(
			{
				externalId: "e1",
				email: "a@example.test",
				emailVerified: true,
				name: null,
				linkedAccounts: [],
				metadata: {},
			},
			"keycloak",
		);
		const salt = new Uint8Array([9, 9, 9, 9]);
		const legacy: LegacyHash = {
			algorithm: "pbkdf2-sha256",
			hash: bytesToBase64(await pbkdf2("right-pass", salt, 500, "SHA-256", 32)),
			salt: bytesToBase64(salt),
			params: { iterations: 500 },
		};
		await store.setPasswordHash(user.id, encodeLegacyHash(legacy));
		return { store, userId: user.id };
	}

	it("rehashes on first success, calls the hook, and later logins use the new hash", async () => {
		const { store, userId } = await setup();
		const seen: unknown[] = [];
		const m = createLazyPasswordMigrator({
			store,
			source: "keycloak",
			onLegacyHashAccepted: (e) => {
				seen.push(e);
			},
		});
		const first = await m.verify(userId, "right-pass");
		expect(first).toEqual({ success: true, data: { valid: true, rehashed: true } });
		expect(seen).toEqual([{ userId, algorithm: "pbkdf2-sha256" }]);
		const stored = (await store.getPasswordHash(userId)) as string;
		expect(stored.startsWith("pbkdf2:")).toBe(true);
		expect(await pbkdf2Verify("right-pass", stored)).toBe(true);
		const second = await m.verify(userId, "right-pass");
		expect(second).toEqual({ success: true, data: { valid: true, rehashed: false } });
		expect(seen).toHaveLength(1);
		const ledger = await store.listMigrations();
		expect(ledger.filter((r) => r.status === "migrated")).toHaveLength(1);
	});

	it("wrong password changes nothing", async () => {
		const { store, userId } = await setup();
		const before = await store.getPasswordHash(userId);
		const hook = vi.fn();
		const m = createLazyPasswordMigrator({ store, onLegacyHashAccepted: hook });
		expect(await m.verify(userId, "wrong")).toEqual({
			success: true,
			data: { valid: false, rehashed: false },
		});
		expect(await store.getPasswordHash(userId)).toBe(before);
		expect(hook).not.toHaveBeenCalled();
	});

	it("a failing hook or rehash never fails a correct login", async () => {
		const { store, userId } = await setup();
		const m = createLazyPasswordMigrator({
			store,
			onLegacyHashAccepted: () => {
				throw new Error("boom");
			},
		});
		expect(await m.verify(userId, "right-pass")).toEqual({
			success: true,
			data: { valid: true, rehashed: true },
		});

		const s2 = await setup();
		const m2 = createLazyPasswordMigrator({
			store: s2.store,
			rehash: async () => {
				throw new Error("db down");
			},
		});
		expect(await m2.verify(s2.userId, "right-pass")).toEqual({
			success: true,
			data: { valid: true, rehashed: false },
		});
	});
});
