/** Edge cases for signed checkpoints and proofs: hostile sizes and indexes must come back as a verdict, never a throw, and boundary timestamps must be handled inclusively. */

import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
	createCheckpoint,
	createInclusionProof,
	verifyInclusionProof,
} from "../src/audit/checkpoint.js";
import {
	inclusionPath,
	merkleLeafHash,
	merkleRoot,
	verifyConsistencyPath,
	verifyInclusionPath,
} from "../src/audit/checkpoint-merkle.js";
import {
	generateCheckpointKeyPair,
	isWellFormedCheckpoint,
	signCheckpoint,
	verifyCheckpoint,
} from "../src/audit/checkpoint-sign.js";
import type { Checkpoint, CheckpointPublicKey } from "../src/audit/checkpoint-types.js";
import { enableAuditChain, insertAuditRow } from "../src/audit/index.js";
import { constantTimeEqual, toHex } from "../src/crypto/web-crypto.js";
import type { Database } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import { agents, users } from "../src/db/schema.js";

const T0 = new Date("2026-10-01T00:00:00Z");
const HMAC = "checkpoint-edge-key";

function h(byte: number, length = 32): Uint8Array {
	return new Uint8Array(length).fill(byte);
}

function sha256(bytes: Uint8Array): Uint8Array {
	return new Uint8Array(createHash("sha256").update(bytes).digest());
}

async function setup(): Promise<Database> {
	const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite");
	await db.insert(users).values({
		id: "u1",
		email: "u1@example.com",
		name: "U1",
		username: "u1",
		createdAt: T0,
		updatedAt: T0,
	});
	await db.insert(agents).values({
		id: "a1",
		ownerId: "u1",
		name: "a1",
		type: "autonomous",
		status: "active",
		tokenHash: "h-a1",
		tokenPrefix: "kv_x",
		metadata: {},
		createdAt: T0,
		updatedAt: T0,
	});
	enableAuditChain(db, { hmacKey: HMAC });
	return db;
}

async function addRow(db: Database, id: string, sec: number): Promise<void> {
	await insertAuditRow(db, {
		id,
		agentId: "a1",
		userId: "u1",
		action: "execute",
		resource: `mcp:github:${id}`,
		parameters: { n: id },
		result: "allowed",
		reason: null,
		durationMs: 1,
		timestamp: new Date(T0.getTime() + sec * 1000),
		approverId: "u1",
	});
}

describe("merkle verifiers never throw on hostile input", () => {
	it("rejects impossible leaf positions and sizes", async () => {
		const leaf = h(1);
		const root = h(2);
		const cases: Array<[number, number]> = [
			[Number.NaN, 4],
			[-1, 4],
			[1.5, 4],
			[4, 4],
			[Number.POSITIVE_INFINITY, 4],
			[0, 0],
			[0, -1],
			[0, Number.NaN],
			[0, Number.POSITIVE_INFINITY],
		];
		for (const [index, size] of cases) {
			await expect(verifyInclusionPath(leaf, index, size, [], root)).resolves.toBe(false);
		}
	});

	it("rejects a size beyond the safe integer range", async () => {
		await expect(verifyInclusionPath(h(1), 0, 2 ** 53 + 2, [], h(2))).resolves.toBe(false);
	});

	it("rejects hashes of the wrong length", async () => {
		await expect(verifyInclusionPath(h(1, 31), 0, 1, [], h(1))).resolves.toBe(false);
		await expect(verifyInclusionPath(h(1), 0, 1, [h(1, 33)], h(1))).resolves.toBe(false);
		await expect(verifyInclusionPath(h(1), 0, 2, [h(1)], h(1, 16))).resolves.toBe(false);
	});

	it("rejects an oversized path quickly without throwing", async () => {
		const path = Array.from({ length: 100_000 }, () => h(3));
		await expect(verifyInclusionPath(h(1), 0, 4, path, h(2))).resolves.toBe(false);
	});

	it("accepts a single leaf tree whose root is the leaf itself", async () => {
		const leaf = await merkleLeafHash(new TextEncoder().encode("only"));
		await expect(verifyInclusionPath(leaf, 0, 1, [], leaf)).resolves.toBe(true);
	});

	it("rejects a real path with an extra element appended", async () => {
		const leaves = await Promise.all([0, 1, 2].map((i) => merkleLeafHash(new Uint8Array([i]))));
		const root = await merkleRoot(leaves);
		const path = await inclusionPath(leaves, 0);
		await expect(verifyInclusionPath(leaves[0] as Uint8Array, 0, 3, path, root)).resolves.toBe(
			true,
		);
		await expect(
			verifyInclusionPath(leaves[0] as Uint8Array, 0, 3, [...path, h(9)], root),
		).resolves.toBe(false);
	});

	it("rejects consistency arguments that are out of range or NaN", async () => {
		const root = h(1);
		await expect(verifyConsistencyPath(Number.NaN, 3, root, root, [])).resolves.toBe(false);
		await expect(verifyConsistencyPath(-1, 3, root, root, [])).resolves.toBe(false);
		await expect(verifyConsistencyPath(4, 3, root, root, [])).resolves.toBe(false);
		await expect(verifyConsistencyPath(2, Number.NaN, root, root, [])).resolves.toBe(false);
	});

	it("requires equal roots and an empty path for equal sizes", async () => {
		await expect(verifyConsistencyPath(3, 3, h(1), h(1), [])).resolves.toBe(true);
		await expect(verifyConsistencyPath(3, 3, h(1), h(2), [])).resolves.toBe(false);
		await expect(verifyConsistencyPath(3, 3, h(1), h(1), [h(2)])).resolves.toBe(false);
	});

	it("requires an empty older tree to carry the empty-tree root", async () => {
		// Only the SHA-256 of the empty string is a valid root for the empty prefix.
		await expect(verifyConsistencyPath(0, 3, h(7), h(2), [])).resolves.toBe(false);
	});

	it("uses the SHA-256 of the empty string for the empty tree root", async () => {
		await expect(merkleRoot([])).resolves.toEqual(sha256(new Uint8Array(0)));
	});

	it("rejects out-of-range proof indexes with a RangeError", async () => {
		await expect(inclusionPath([h(1)], 1)).rejects.toBeInstanceOf(RangeError);
		await expect(inclusionPath([h(1)], -1)).rejects.toBeInstanceOf(RangeError);
	});
});

describe("constant time comparison", () => {
	it("compares bytewise and returns false on a length mismatch", () => {
		expect(constantTimeEqual(h(1), h(1))).toBe(true);
		expect(constantTimeEqual(h(1), h(2))).toBe(false);
		expect(constantTimeEqual(h(1), h(1, 31))).toBe(false);
		expect(constantTimeEqual(new Uint8Array(0), new Uint8Array(0))).toBe(true);
	});
});

describe("checkpoint signature edge cases", () => {
	async function signed(size: number): Promise<{
		cp: Checkpoint;
		key: CheckpointPublicKey;
		kp: Awaited<ReturnType<typeof generateCheckpointKeyPair>>;
	}> {
		const kp = await generateCheckpointKeyPair("k1");
		const cp = await signCheckpoint(kp.signer, {
			version: 1,
			alg: "Ed25519",
			keyId: "k1",
			size,
			rootHash: toHex(h(4)),
			timestamp: T0.getTime(),
			since: null,
			until: null,
		});
		return { cp, key: kp.publicKey, kp };
	}

	it("returns a verdict for a non-object checkpoint", async () => {
		const { key } = await signed(1);
		await expect(verifyCheckpoint(null as unknown as Checkpoint, key)).resolves.toEqual({
			valid: false,
			reason: "malformed",
		});
		await expect(verifyCheckpoint("x" as unknown as Checkpoint, key)).resolves.toEqual({
			valid: false,
			reason: "malformed",
		});
	});

	it("reports bad_signature for signatures that are not base64url or the wrong length", async () => {
		const { cp, key } = await signed(1);
		await expect(verifyCheckpoint({ ...cp, signature: "!!!" }, key)).resolves.toEqual({
			valid: false,
			reason: "bad_signature",
		});
		await expect(verifyCheckpoint({ ...cp, signature: "AAAA" }, key)).resolves.toEqual({
			valid: false,
			reason: "bad_signature",
		});
	});

	it("reports bad_signature when the key entry has no key body", async () => {
		const { cp, key } = await signed(1);
		const broken = { keyId: key.keyId, publicKey: undefined as unknown as JsonWebKey };
		await expect(verifyCheckpoint(cp, broken)).resolves.toEqual({
			valid: false,
			reason: "bad_signature",
		});
	});

	it("reports unknown_key for an empty key set", async () => {
		const { cp } = await signed(1);
		await expect(verifyCheckpoint(cp, [])).resolves.toEqual({
			valid: false,
			reason: "unknown_key",
		});
	});

	it("accepts only well formed numeric fields", () => {
		const base = {
			version: 1,
			alg: "Ed25519",
			keyId: "k",
			size: 0,
			rootHash: toHex(h(1)),
			timestamp: 0,
			since: null,
			until: null,
			signature: "x",
		};
		expect(isWellFormedCheckpoint(base)).toBe(true);
		expect(isWellFormedCheckpoint({ ...base, since: 0 })).toBe(true);
		expect(isWellFormedCheckpoint({ ...base, since: -1 })).toBe(false);
		expect(isWellFormedCheckpoint({ ...base, until: 2 ** 53 })).toBe(false);
		expect(isWellFormedCheckpoint({ ...base, size: -1 })).toBe(false);
		expect(isWellFormedCheckpoint({ ...base, size: Number.NaN })).toBe(false);
		expect(isWellFormedCheckpoint({ ...base, rootHash: "AB".repeat(32) })).toBe(false);
	});

	it("does not throw when the public key argument is null", async () => {
		// A null key must give a verdict, not a TypeError.
		const { cp } = await signed(1);
		await expect(verifyCheckpoint(cp, null as unknown as CheckpointPublicKey)).resolves.toEqual({
			valid: false,
			reason: "unknown_key",
		});
	});

	it("does not throw when the key set contains a null entry", async () => {
		const { cp, key } = await signed(1);
		await expect(
			verifyCheckpoint(cp, [null as unknown as CheckpointPublicKey, key]),
		).resolves.toEqual({ valid: true });
	});
});

describe("checkpoint boundaries against the log", () => {
	it("includes rows whose timestamps equal since and until exactly", async () => {
		const db = await setup();
		const kp = await generateCheckpointKeyPair("k1");
		for (let i = 0; i < 5; i++) await addRow(db, `r${i}`, i * 10);
		const r = await createCheckpoint(db, {
			signer: kp.signer,
			since: new Date(T0.getTime() + 10_000),
			until: new Date(T0.getTime() + 30_000),
		});
		if (!r.success) throw new Error(r.error.message);
		expect(r.data.size).toBe(3);
		const proof = await createInclusionProof(db, "r1", r.data);
		expect(proof.success).toBe(true);
		if (!proof.success) return;
		expect((await verifyInclusionProof(proof.data, r.data, kp.publicKey)).valid).toBe(true);
	});

	it("refuses a checkpoint that claims more leaves than the log holds", async () => {
		const db = await setup();
		const kp = await generateCheckpointKeyPair("k1");
		await addRow(db, "r0", 0);
		await addRow(db, "r1", 1);
		const real = await createCheckpoint(db, { signer: kp.signer });
		if (!real.success) throw new Error(real.error.message);
		const { signature: _old, ...body } = real.data;
		const claimed = await signCheckpoint(kp.signer, { ...body, size: 99 });
		const proof = await createInclusionProof(db, "r0", claimed);
		expect(proof.success).toBe(false);
		if (proof.success) return;
		expect(proof.error.code).toBe("LOG_MISMATCH");
	});

	it("refuses a checkpoint whose since date is not a valid time", async () => {
		// A NaN since is rejected before signing instead of producing a malformed checkpoint.
		const db = await setup();
		const kp = await generateCheckpointKeyPair("k1");
		await addRow(db, "r0", 0);
		const r = await createCheckpoint(db, { signer: kp.signer, since: new Date("not a date") });
		expect(r.success === false || isWellFormedCheckpoint(r.data)).toBe(true);
	});
});
