/** Error and edge paths of signed checkpoints, proofs, receipts, signing and the memory store. */

import { eq } from "drizzle-orm";
import { beforeEach, describe, expect, it } from "vitest";
import {
	createCheckpoint,
	createConsistencyProof,
	createInclusionProof,
	loadCheckpointTree,
	verifyConsistencyProof,
	verifyInclusionProof,
} from "../src/audit/checkpoint.js";
import { createReceipt, verifyReceipt } from "../src/audit/checkpoint-receipt.js";
import {
	createEd25519Signer,
	generateCheckpointKeyPair,
	isWellFormedCheckpoint,
	signCheckpoint,
	verifyCheckpoint,
} from "../src/audit/checkpoint-sign.js";
import { createMemoryCheckpointStore } from "../src/audit/checkpoint-store.js";
import type {
	Checkpoint,
	CheckpointSigner,
	ConsistencyProof,
	InclusionProof,
	Receipt,
} from "../src/audit/checkpoint-types.js";
import { enableAuditChain, insertAuditRow } from "../src/audit/index.js";
import type { Database } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import { agents, auditLogs, users } from "../src/db/schema.js";

const HMAC = "checkpoint-coverage-key";
const T0 = new Date("2026-10-01T00:00:00Z");

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
	for (const id of ["a1", "a2"]) {
		await db.insert(agents).values({
			id,
			ownerId: "u1",
			name: id,
			type: "autonomous",
			status: "active",
			tokenHash: `h-${id}`,
			tokenPrefix: "kv_x",
			metadata: {},
			createdAt: T0,
			updatedAt: T0,
		});
	}
	enableAuditChain(db, { hmacKey: HMAC });
	return db;
}

/** A database with no tables: every query fails with a real driver error. */
async function bareDatabase(): Promise<Database> {
	return createDatabase({ provider: "sqlite", url: ":memory:" });
}

async function add(db: Database, id: string, sec: number) {
	await insertAuditRow(db, {
		id,
		agentId: sec % 2 ? "a1" : "a2",
		userId: "u1",
		action: "execute",
		resource: `mcp:github:${id}`,
		parameters: { n: sec },
		result: "allowed",
		reason: null,
		durationMs: 5,
		timestamp: new Date(T0.getTime() + sec * 1000),
		approverId: "u1",
	});
}

function unwrap<T>(
	result: { success: true; data: T } | { success: false; error: { code: string } },
): T {
	if (!result.success) throw new Error(`unexpected failure ${result.error.code}`);
	return result.data;
}

describe("createCheckpoint failure paths", () => {
	let db: Database;
	let kp: Awaited<ReturnType<typeof generateCheckpointKeyPair>>;
	beforeEach(async () => {
		db = await setup();
		kp = await generateCheckpointKeyPair("k1");
	});

	it("rejects a now override that is not a valid date", async () => {
		await add(db, "r1", 1);
		const r = await createCheckpoint(db, { signer: kp.signer, now: new Date("not a date") });
		expect(r).toMatchObject({ success: false, error: { code: "INVALID_TIMESTAMP" } });
	});

	it("reports CHECKPOINT_FAILED when the signer returns a short signature", async () => {
		await add(db, "r1", 1);
		const shortSigner: CheckpointSigner = {
			keyId: "k1",
			sign: async () => new Uint8Array(10),
		};
		const r = await createCheckpoint(db, { signer: shortSigner });
		expect(r.success).toBe(false);
		if (r.success) return;
		expect(r.error.code).toBe("CHECKPOINT_FAILED");
		expect(r.error.message).toContain("64 byte Ed25519 signature");
	});

	it("reports the driver error message when the audit table cannot be read", async () => {
		const bare = await bareDatabase();
		const r = await createCheckpoint(bare, { signer: kp.signer, hmacKey: HMAC });
		expect(r.success).toBe(false);
		if (r.success) return;
		expect(r.error.code).toBe("CHECKPOINT_FAILED");
		expect(r.error.message.length).toBeGreaterThan(0);
		expect(r.error.message).not.toBe("Unknown");
	});

	it("falls back to Unknown when the failure is not an Error", async () => {
		const broken = {
			select() {
				throw "boom";
			},
		} as unknown as Database;
		const r = await createCheckpoint(broken, { signer: kp.signer, hmacKey: HMAC });
		expect(r).toEqual({
			success: false,
			error: { code: "CHECKPOINT_FAILED", message: "Unknown" },
		});
	});

	it("stores the checkpoint it returns when a store is given", async () => {
		await add(db, "r1", 1);
		const store = createMemoryCheckpointStore();
		const cp = unwrap(await createCheckpoint(db, { signer: kp.signer, store }));
		expect(await store.latest()).toEqual(cp);
	});
});

describe("inclusion and consistency proof failure paths", () => {
	let db: Database;
	let kp: Awaited<ReturnType<typeof generateCheckpointKeyPair>>;
	let c2: Checkpoint;
	let c3: Checkpoint;

	beforeEach(async () => {
		db = await setup();
		kp = await generateCheckpointKeyPair("k1");
		await add(db, "r1", 1);
		await add(db, "r2", 2);
		c2 = unwrap(await createCheckpoint(db, { signer: kp.signer }));
		await add(db, "r3", 3);
		c3 = unwrap(await createCheckpoint(db, { signer: kp.signer }));
	});

	it("rejects a malformed checkpoint for an inclusion proof", async () => {
		const bad = { ...c2, rootHash: "not-hex" } as Checkpoint;
		const r = await createInclusionProof(db, "r1", bad);
		expect(r).toMatchObject({ success: false, error: { code: "INVALID_CHECKPOINT" } });
	});

	it("reports LOG_MISMATCH when the checkpoint commits to more rows than the log holds", async () => {
		const inflated = { ...c3, size: c3.size + 1 };
		const r = await createInclusionProof(db, "r1", inflated);
		expect(r).toMatchObject({ success: false, error: { code: "LOG_MISMATCH" } });
	});

	it("reports LOG_MISMATCH when a covered row is rewritten after the checkpoint", async () => {
		await db.update(auditLogs).set({ reason: "rewritten" }).where(eq(auditLogs.id, "r2"));
		const r = await createInclusionProof(db, "r1", c3);
		expect(r).toMatchObject({ success: false, error: { code: "LOG_MISMATCH" } });
		const tree = await loadCheckpointTree(db, c3, HMAC);
		expect(tree).toMatchObject({ success: false, error: { code: "LOG_MISMATCH" } });
	});

	it("reports PROOF_FAILED when the log cannot be read for an inclusion proof", async () => {
		const r = await createInclusionProof(await bareDatabase(), "r1", c2, { hmacKey: HMAC });
		expect(r).toMatchObject({ success: false, error: { code: "PROOF_FAILED" } });
	});

	it("rejects an older checkpoint larger than the newer one", async () => {
		const r = await createConsistencyProof(db, c3, c2);
		expect(r).toMatchObject({ success: false, error: { code: "INVALID_ORDER" } });
	});

	it("rejects a malformed checkpoint for a consistency proof", async () => {
		const r = await createConsistencyProof(db, { ...c2, size: -1 } as Checkpoint, c3);
		expect(r).toMatchObject({ success: false, error: { code: "INVALID_CHECKPOINT" } });
	});

	it("rejects checkpoints that cover different time ranges", async () => {
		const scoped = unwrap(await createCheckpoint(db, { signer: kp.signer, since: T0 }));
		const r = await createConsistencyProof(db, c2, scoped);
		expect(r).toMatchObject({ success: false, error: { code: "SCOPE_MISMATCH" } });
	});

	it("reports LOG_MISMATCH when the newer checkpoint root does not match the log", async () => {
		const forged = { ...c3, rootHash: "cd".repeat(32) };
		const r = await createConsistencyProof(db, c2, forged);
		expect(r).toMatchObject({ success: false, error: { code: "LOG_MISMATCH" } });
	});

	it("rejects an older checkpoint whose root is not a prefix of the current log", async () => {
		const forged = { ...c2, rootHash: "ab".repeat(32) };
		const r = await createConsistencyProof(db, forged, c3);
		expect(r).toMatchObject({ success: false, error: { code: "LOG_MISMATCH" } });
	});

	it("reports PROOF_FAILED when the log cannot be read for a consistency proof", async () => {
		const r = await createConsistencyProof(await bareDatabase(), c2, c3, { hmacKey: HMAC });
		expect(r).toMatchObject({ success: false, error: { code: "PROOF_FAILED" } });
	});

	it("verifies a genuine consistency proof and rejects a tampered one", async () => {
		const proof = unwrap(await createConsistencyProof(db, c2, c3));
		expect(await verifyConsistencyProof(proof, c2, c3, kp.publicKey)).toEqual({ valid: true });
		const padded: ConsistencyProof = { ...proof, path: [...proof.path, "00".repeat(32)] };
		expect(await verifyConsistencyProof(padded, c2, c3, kp.publicKey)).toEqual({
			valid: false,
			reason: "bad_proof",
		});
	});

	it.each([
		["a null proof", null],
		["a proof of another version", { version: 2, oldSize: 2, newSize: 3, path: [] }],
		["a proof whose path is not an array", { version: 1, oldSize: 2, newSize: 3, path: "x" }],
		["a proof with a non-hex path entry", { version: 1, oldSize: 2, newSize: 3, path: ["zz"] }],
	])("classifies %s as malformed in a consistency check", async (_label, proof) => {
		const r = await verifyConsistencyProof(
			proof as unknown as ConsistencyProof,
			c2,
			c3,
			kp.publicKey,
		);
		expect(r).toEqual({ valid: false, reason: "malformed" });
	});

	it("reports the failure of the newer checkpoint signature first", async () => {
		const proof = unwrap(await createConsistencyProof(db, c2, c3));
		const forgedNewer = { ...c3, timestamp: c3.timestamp + 1 };
		expect(await verifyConsistencyProof(proof, c2, forgedNewer, kp.publicKey)).toEqual({
			valid: false,
			reason: "bad_signature",
		});
	});

	it("reports size_mismatch when the proof sizes disagree with the checkpoints", async () => {
		const proof = { version: 1 as const, oldSize: 1, newSize: c3.size, path: [] };
		expect(await verifyConsistencyProof(proof, c2, c3, kp.publicKey)).toEqual({
			valid: false,
			reason: "size_mismatch",
		});
	});

	it("reports scope_mismatch when the checkpoints cover different ranges", async () => {
		const scoped = unwrap(await createCheckpoint(db, { signer: kp.signer, since: T0 }));
		const proof = { version: 1 as const, oldSize: c2.size, newSize: scoped.size, path: [] };
		expect(await verifyConsistencyProof(proof, c2, scoped, kp.publicKey)).toEqual({
			valid: false,
			reason: "scope_mismatch",
		});
	});

	it("rejects a checkpoint signed by an unknown key when verifying a consistency proof", async () => {
		const other = await generateCheckpointKeyPair("other");
		const proof = unwrap(await createConsistencyProof(db, c2, c3));
		expect(await verifyConsistencyProof(proof, c2, c3, other.publicKey)).toEqual({
			valid: false,
			reason: "unknown_key",
		});
	});

	it.each([
		["a null proof", null],
		["a non-object proof", "proof"],
		[
			"a proof of another version",
			{ version: 2, rowId: "r1", leafIndex: 0, treeSize: 3, leafHash: "a".repeat(64), path: [] },
		],
		[
			"a leaf hash that is not hex",
			{ version: 1, rowId: "r1", leafIndex: 0, treeSize: 3, leafHash: "xyz", path: [] },
		],
		[
			"a path that is not an array",
			{ version: 1, rowId: "r1", leafIndex: 0, treeSize: 3, leafHash: "a".repeat(64), path: {} },
		],
		[
			"a non-integer leaf index",
			{ version: 1, rowId: "r1", leafIndex: 1.5, treeSize: 3, leafHash: "a".repeat(64), path: [] },
		],
	])("classifies %s as malformed in an inclusion check", async (_label, proof) => {
		const r = await verifyInclusionProof(proof as unknown as InclusionProof, c3, kp.publicKey);
		expect(r).toEqual({ valid: false, reason: "malformed" });
	});

	it("reports bad_proof when the leaf index does not match the path", async () => {
		const proof = unwrap(await createInclusionProof(db, "r1", c3));
		const moved = { ...proof, leafIndex: proof.leafIndex + 1 };
		expect(await verifyInclusionProof(moved, c3, kp.publicKey)).toEqual({
			valid: false,
			reason: "bad_proof",
		});
	});

	it("reports size_mismatch when the proof tree size differs from the checkpoint", async () => {
		const proof = unwrap(await createInclusionProof(db, "r1", c3));
		expect(await verifyInclusionProof({ ...proof, treeSize: 2 }, c3, kp.publicKey)).toEqual({
			valid: false,
			reason: "size_mismatch",
		});
	});

	it("does not accept an inclusion proof against a forged checkpoint signature", async () => {
		const proof = unwrap(await createInclusionProof(db, "r1", c3));
		const forged = { ...c3, timestamp: c3.timestamp + 1 };
		expect(await verifyInclusionProof(proof, forged, kp.publicKey)).toEqual({
			valid: false,
			reason: "bad_signature",
		});
	});
});

describe("signing and verification edges", () => {
	it("refuses a signer that returns a signature of the wrong length", async () => {
		const short: CheckpointSigner = { keyId: "k", sign: async () => new Uint8Array(63) };
		await expect(
			signCheckpoint(short, {
				version: 1,
				alg: "Ed25519",
				keyId: "k",
				size: 0,
				rootHash: "a".repeat(64),
				timestamp: 1,
				since: null,
				until: null,
			}),
		).rejects.toThrow("64 byte Ed25519 signature");
	});

	it("rejects a public key whose key type is not OKP", async () => {
		const kp = await generateCheckpointKeyPair("k1");
		const cp = await signCheckpoint(kp.signer, {
			version: 1,
			alg: "Ed25519",
			keyId: "k1",
			size: 0,
			rootHash: "a".repeat(64),
			timestamp: 1,
			since: null,
			until: null,
		});
		const rsa = {
			keyId: "k1",
			publicKey: { kty: "RSA", crv: "Ed25519", x: "AAAA" },
		} as unknown as Parameters<typeof verifyCheckpoint>[1];
		expect(await verifyCheckpoint(cp, rsa)).toEqual({ valid: false, reason: "unsupported_alg" });
	});

	it("rejects a non-Ed25519 algorithm and malformed input without throwing", async () => {
		const kp = await generateCheckpointKeyPair("k1");
		const cp = await signCheckpoint(kp.signer, {
			version: 1,
			alg: "Ed25519",
			keyId: "k1",
			size: 0,
			rootHash: "a".repeat(64),
			timestamp: 1,
			since: null,
			until: null,
		});
		expect(await verifyCheckpoint({ ...cp, alg: "RS256" } as Checkpoint, kp.publicKey)).toEqual({
			valid: false,
			reason: "unsupported_alg",
		});
		expect(await verifyCheckpoint({ bogus: true } as unknown as Checkpoint, kp.publicKey)).toEqual({
			valid: false,
			reason: "malformed",
		});
		expect(await verifyCheckpoint(cp, [null as unknown as typeof kp.publicKey])).toEqual({
			valid: false,
			reason: "unknown_key",
		});
	});

	it("reports bad_signature for a signature of the wrong length", async () => {
		const kp = await generateCheckpointKeyPair("k1");
		const cp = await signCheckpoint(kp.signer, {
			version: 1,
			alg: "Ed25519",
			keyId: "k1",
			size: 0,
			rootHash: "a".repeat(64),
			timestamp: 1,
			since: null,
			until: null,
		});
		expect(await verifyCheckpoint({ ...cp, signature: "AAAA" }, kp.publicKey)).toEqual({
			valid: false,
			reason: "bad_signature",
		});
	});

	it("rejects a checkpoint whose shape is wrong", () => {
		expect(isWellFormedCheckpoint(null)).toBe(false);
		expect(isWellFormedCheckpoint({ version: 1 })).toBe(false);
	});

	it("builds a signer from a private JWK that verifies with the matching public key", async () => {
		const kp = await generateCheckpointKeyPair("k9");
		const signer = await createEd25519Signer(kp.privateKeyJwk, "k9");
		const cp = await signCheckpoint(signer, {
			version: 1,
			alg: "Ed25519",
			keyId: "k9",
			size: 0,
			rootHash: "a".repeat(64),
			timestamp: 1,
			since: null,
			until: null,
		});
		expect(await verifyCheckpoint(cp, kp.publicKey)).toEqual({ valid: true });
	});
});

describe("memory checkpoint store", () => {
	const base = {
		version: 1 as const,
		alg: "Ed25519",
		keyId: "k",
		rootHash: "a".repeat(64),
		since: null,
		until: null,
	};

	it("orders by size, then timestamp, and ignores exact duplicates", async () => {
		const store = createMemoryCheckpointStore();
		const late: Checkpoint = { ...base, size: 1, timestamp: 200, signature: "s-late" };
		const early: Checkpoint = { ...base, size: 1, timestamp: 100, signature: "s-early" };
		const big: Checkpoint = { ...base, size: 2, timestamp: 50, signature: "s-big" };
		await store.put(late);
		await store.put(early);
		await store.put(big);
		await store.put({ ...early });
		expect((await store.getBySize(1)).map((c) => c.timestamp)).toEqual([100, 200]);
		expect((await store.list()).length).toBe(3);
		expect((await store.latest())?.signature).toBe("s-big");
	});

	it("returns copies, so callers cannot change stored checkpoints", async () => {
		const store = createMemoryCheckpointStore();
		await store.put({ ...base, size: 1, timestamp: 1, signature: "s" });
		const first = await store.latest();
		if (first) first.size = 99;
		expect((await store.latest())?.size).toBe(1);
	});

	it("rejects instead of throwing when an entry cannot be compared", async () => {
		const store = createMemoryCheckpointStore();
		await store.put({ ...base, size: 1, timestamp: 1, signature: "s" });
		await expect(store.put(null as unknown as Checkpoint)).rejects.toThrow();
	});

	it("returns undefined from latest on an empty store", async () => {
		expect(await createMemoryCheckpointStore().latest()).toBeUndefined();
	});
});

describe("receipt failure and tamper paths", () => {
	let db: Database;
	let kp: Awaited<ReturnType<typeof generateCheckpointKeyPair>>;
	let cp: Checkpoint;
	let receipt: Receipt;

	beforeEach(async () => {
		db = await setup();
		kp = await generateCheckpointKeyPair("k1");
		await add(db, "r1", 1);
		await add(db, "r2", 2);
		cp = unwrap(await createCheckpoint(db, { signer: kp.signer }));
		receipt = unwrap(await createReceipt(db, "r1", cp, { reveal: ["action"] }));
	});

	it("reports RECEIPT_FAILED when the log cannot be read", async () => {
		const r = await createReceipt(await bareDatabase(), "r1", cp, {
			reveal: [],
			hmacKey: HMAC,
		});
		expect(r).toMatchObject({ success: false, error: { code: "RECEIPT_FAILED" } });
		expect(r.success).toBe(false);
		if (!r.success) expect(r.error.message.length).toBeGreaterThan(0);
	});

	it("reports ROW_NOT_FOUND for a row outside the checkpoint", async () => {
		const r = await createReceipt(db, "missing", cp, { reveal: [] });
		expect(r).toMatchObject({ success: false, error: { code: "ROW_NOT_FOUND" } });
	});

	it("reports RECEIPT_FAILED with Unknown when the failure is not an Error", async () => {
		const broken = {
			select() {
				throw "boom";
			},
		} as unknown as Database;
		const r = await createReceipt(broken, "r1", cp, { reveal: [], hmacKey: HMAC });
		expect(r).toEqual({
			success: false,
			error: { code: "RECEIPT_FAILED", message: "Unknown" },
		});
	});

	it("builds a receipt for a row without a hash version using the version 1 fields", async () => {
		await db.update(auditLogs).set({ hashVersion: null }).where(eq(auditLogs.id, "r2"));
		const plain = unwrap(await createCheckpoint(db, { signer: kp.signer }));
		const legacy = unwrap(await createReceipt(db, "r2", plain, { reveal: ["agentId"] }));
		expect(legacy.decision.hashVersion).toBe(1);
		expect(legacy.decision.revealed.agentId).toBeDefined();
		expect(await verifyReceipt(legacy, kp.publicKey)).toEqual({ valid: true });
	});

	it("accepts a genuine receipt", async () => {
		expect(await verifyReceipt(receipt, kp.publicKey)).toEqual({ valid: true });
	});

	it("classifies a commitment that is not hex as malformed", async () => {
		const tampered: Receipt = {
			...receipt,
			decision: {
				...receipt.decision,
				commitments: { ...receipt.decision.commitments, resource: "nope" },
			},
		};
		expect(await verifyReceipt(tampered, kp.publicKey)).toEqual({
			valid: false,
			reason: "malformed",
		});
	});

	it("classifies a revealed field that is not an object as malformed", async () => {
		const tampered: Receipt = {
			...receipt,
			decision: {
				...receipt.decision,
				revealed: { action: null as unknown as { value: unknown; salt: string } },
			},
		};
		expect(await verifyReceipt(tampered, kp.publicKey)).toEqual({
			valid: false,
			reason: "malformed",
		});
	});

	it("classifies a revealed salt that is not hex as malformed", async () => {
		const tampered: Receipt = {
			...receipt,
			decision: {
				...receipt.decision,
				revealed: { action: { value: "execute", salt: "not-a-salt" } },
			},
		};
		expect(await verifyReceipt(tampered, kp.publicKey)).toEqual({
			valid: false,
			reason: "malformed",
		});
	});

	it("reports bad_commitment when a revealed value cannot be encoded", async () => {
		const cyclic: Record<string, unknown> = {};
		cyclic.self = cyclic;
		const tampered: Receipt = {
			...receipt,
			decision: {
				...receipt.decision,
				revealed: { action: { value: cyclic, salt: receipt.decision.revealed.action?.salt ?? "" } },
			},
		};
		expect(await verifyReceipt(tampered, kp.publicKey)).toEqual({
			valid: false,
			reason: "bad_commitment",
		});
	});

	it("reports leaf_mismatch when a revealed value differs from the committed one", async () => {
		const tampered: Receipt = {
			...receipt,
			decision: {
				...receipt.decision,
				revealed: {
					action: { value: "delete", salt: receipt.decision.revealed.action?.salt ?? "" },
				},
			},
		};
		expect(await verifyReceipt(tampered, kp.publicKey)).toEqual({
			valid: false,
			reason: "leaf_mismatch",
		});
	});
});
