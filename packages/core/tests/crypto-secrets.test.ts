import { describe, expect, it } from "vitest";
import { createSecretRing, SecretRing } from "../src/crypto/secrets.js";

const A = "a".repeat(32);
const B = "b".repeat(32);
const C = "c".repeat(40);

describe("SecretRing construction", () => {
	it("accepts a single string", () => {
		expect(createSecretRing(A).size).toBe(1);
	});

	it("accepts an array, first is current", () => {
		const ring = createSecretRing([A, B]);
		expect(ring.size).toBe(2);
	});

	it("accepts { id, secret } entries", () => {
		const ring = createSecretRing([
			{ id: "k2", secret: B },
			{ id: "k1", secret: A },
		]);
		expect(ring.currentId).toBe("k2");
	});

	it("rejects short secrets", () => {
		expect(() => createSecretRing("short")).toThrow(/at least 32/);
		expect(() => createSecretRing([A, "short"])).toThrow(/at least 32/);
	});

	it("measures bytes, not characters", () => {
		// 11 characters but 33 bytes in UTF-8
		expect(() => createSecretRing("€".repeat(11))).not.toThrow();
	});

	it("honours a custom minBytes", () => {
		expect(() => createSecretRing("x", { minBytes: 1 })).not.toThrow();
		expect(() => createSecretRing("", { minBytes: 1 })).toThrow(/empty/);
	});

	it("rejects empty list, empty secret and duplicates", () => {
		expect(() => createSecretRing([])).toThrow(/at least one/);
		expect(() => createSecretRing("")).toThrow(/empty/);
		expect(() => createSecretRing([A, A])).toThrow(/duplicate/);
		expect(() =>
			createSecretRing([
				{ id: "k", secret: A },
				{ id: "k", secret: B },
			]),
		).toThrow(/duplicate key id/);
	});

	it("rejects bad key ids and mixed id usage is allowed", () => {
		expect(() => createSecretRing([{ id: "a.b", secret: A }])).toThrow(/key id/);
		expect(() => createSecretRing([{ id: "", secret: A }])).toThrow(/key id/);
		expect(() => createSecretRing([{ id: "k1", secret: A }, B])).not.toThrow();
	});

	it("never leaks secrets in errors, JSON or inspection", () => {
		let message = "";
		try {
			createSecretRing([A, A]);
		} catch (e) {
			message = (e as Error).message;
		}
		expect(message).not.toContain(A);
		const ring = createSecretRing([A, B]);
		expect(JSON.stringify(ring)).not.toContain(A);
		expect(String(ring)).not.toContain(B);
		expect(SecretRing.from(ring)).toBe(ring);
	});
});

describe("SecretRing sign and verify", () => {
	it("round trips with the current key", async () => {
		const ring = createSecretRing(A);
		const { signature } = await ring.sign("hello");
		expect(await ring.verify("hello", signature)).toBe(true);
		expect(await ring.verify("hellp", signature)).toBe(false);
	});

	it("old key still verifies after rotation", async () => {
		const before = createSecretRing(A);
		const { signature } = await before.sign("data");
		const after = createSecretRing([B, A]);
		expect(await after.verify("data", signature)).toBe(true);
		const fresh = await after.sign("data");
		expect(await before.verify("data", fresh.signature)).toBe(false);
	});

	it("removed key stops verifying", async () => {
		const old = createSecretRing([B, A]);
		const { signature } = await old.sign("data");
		const rotated = createSecretRing(B);
		const viaOld = await createSecretRing(A).sign("data");
		expect(await rotated.verify("data", viaOld.signature)).toBe(false);
		expect(await rotated.verify("data", signature)).toBe(true);
	});

	it("signs with the first key only", async () => {
		const ring = createSecretRing([B, A]);
		const { signature } = await ring.sign("x");
		expect(await createSecretRing(B).verify("x", signature)).toBe(true);
		expect(await createSecretRing(A).verify("x", signature)).toBe(false);
	});

	it("detects tampering and wrong lengths", async () => {
		const ring = createSecretRing([A, B]);
		const { signature } = await ring.sign("data");
		const bad = new Uint8Array(signature);
		bad[0] = (bad[0] ?? 0) ^ 1;
		expect(await ring.verify("data", bad)).toBe(false);
		expect(await ring.verify("data", signature.slice(0, 10))).toBe(false);
		expect(await ring.verify("data", new Uint8Array(0))).toBe(false);
	});

	it("emits the key id and prefers it on verify", async () => {
		const ring = createSecretRing([
			{ id: "k2", secret: B },
			{ id: "k1", secret: A },
		]);
		const out = await ring.sign("data");
		expect(out.kid).toBe("k2");
		expect(await ring.verify("data", out.signature, out.kid)).toBe(true);
		const old = await createSecretRing([{ id: "k1", secret: A }]).sign("data");
		expect(old.kid).toBe("k1");
		expect(await ring.verify("data", old.signature, "k1")).toBe(true);
		// A wrong or unknown kid never blocks verification by other keys.
		expect(await ring.verify("data", old.signature, "zzz")).toBe(true);
		expect(await ring.verify("data", old.signature, "k2")).toBe(true);
	});

	it("verifies against every key without early exit (timing shape smoke test)", async () => {
		const ring = createSecretRing([A, B, C]);
		const first = await ring.sign("m");
		const last = await createSecretRing(C).sign("m");
		expect(await ring.verify("m", first.signature)).toBe(true);
		expect(await ring.verify("m", last.signature)).toBe(true);
		expect(ring.lastVerifyAttempts).toBe(3);
	});
});
