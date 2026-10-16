/**
 * Signed audit checkpoints, inclusion proofs, consistency proofs and receipts.
 */

import { eq } from "drizzle-orm";
import { beforeEach, describe, expect, it } from "vitest";
import {
	createCheckpoint,
	createConsistencyProof,
	createInclusionProof,
	verifyConsistencyProof,
	verifyInclusionProof,
} from "../src/audit/checkpoint.js";
import { createReceipt, verifyReceipt } from "../src/audit/checkpoint-receipt.js";
import { generateCheckpointKeyPair, verifyCheckpoint } from "../src/audit/checkpoint-sign.js";
import { createMemoryCheckpointStore } from "../src/audit/checkpoint-store.js";
import type { Checkpoint, Receipt } from "../src/audit/checkpoint-types.js";
import { enableAuditChain, insertAuditRow } from "../src/audit/index.js";
import type { Database } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import { agents, auditLogs, users } from "../src/db/schema.js";

const HMAC = "checkpoint-test-key";
const T0 = new Date("2026-10-01T00:00:00Z");
const EMPTY_ROOT = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

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

async function add(db: Database, id: string, agentId: string, sec: number, extra = {}) {
	await insertAuditRow(db, {
		id,
		agentId,
		userId: "u1",
		action: "execute",
		resource: `mcp:github:${id}`,
		parameters: { secret: `param-of-${id}` },
		result: "allowed",
		reason: null,
		durationMs: 5,
		timestamp: new Date(T0.getTime() + sec * 1000),
		approverId: "u1",
		...extra,
	});
}

async function addN(db: Database, from: number, to: number) {
	for (let i = from; i <= to; i++) await add(db, `r${i}`, i % 2 ? "a1" : "a2", i);
}

describe("audit checkpoints", () => {
	let db: Database;
	let kp: Awaited<ReturnType<typeof generateCheckpointKeyPair>>;
	beforeEach(async () => {
		db = await setup();
		kp = await generateCheckpointKeyPair("k1");
	});

	async function cp(opts: { now?: Date; since?: Date } = {}): Promise<Checkpoint> {
		const r = await createCheckpoint(db, { signer: kp.signer, ...opts });
		if (!r.success) throw new Error(r.error.message);
		return r.data;
	}

	it("checkpoints an empty log", async () => {
		const c = await cp();
		expect(c).toMatchObject({ size: 0, rootHash: EMPTY_ROOT, alg: "Ed25519", keyId: "k1" });
		expect(await verifyCheckpoint(c, kp.publicKey)).toEqual({ valid: true });
		const proof = await createInclusionProof(db, "nope", c);
		expect(proof).toMatchObject({ success: false, error: { code: "ROW_NOT_FOUND" } });
	});

	it("handles a single row and every size up to 9", async () => {
		await addN(db, 1, 1);
		const c1 = await cp();
		expect(c1.size).toBe(1);
		const p1 = await createInclusionProof(db, "r1", c1);
		if (!p1.success) throw new Error(p1.error.message);
		expect(p1.data.path).toEqual([]);
		expect(await verifyInclusionProof(p1.data, c1, kp.publicKey)).toEqual({ valid: true });

		for (let n = 2; n <= 9; n++) {
			await addN(db, n, n);
			const c = await cp();
			expect(c.size).toBe(n);
			for (let i = 1; i <= n; i++) {
				const p = await createInclusionProof(db, `r${i}`, c);
				if (!p.success) throw new Error(p.error.message);
				expect(await verifyInclusionProof(p.data, c, kp.publicKey)).toEqual({ valid: true });
			}
		}
	});

	it("rejects tampered checkpoints, wrong keys and algorithm confusion", async () => {
		await addN(db, 1, 3);
		const c = await cp();
		const other = await generateCheckpointKeyPair("k1");
		expect(await verifyCheckpoint(c, other.publicKey)).toEqual({
			valid: false,
			reason: "bad_signature",
		});
		expect(await verifyCheckpoint(c, { ...kp.publicKey, keyId: "k2" })).toEqual({
			valid: false,
			reason: "unknown_key",
		});
		expect(await verifyCheckpoint({ ...c, size: 4 }, kp.publicKey)).toMatchObject({ valid: false });
		expect(await verifyCheckpoint({ ...c, rootHash: "0".repeat(64) }, kp.publicKey)).toMatchObject({
			valid: false,
		});
		expect(
			await verifyCheckpoint({ ...c, timestamp: c.timestamp + 1 }, kp.publicKey),
		).toMatchObject({
			valid: false,
		});
		for (const alg of ["none", "HS256", "ES256", "EdDSA"]) {
			const forged = { ...c, alg } as unknown as Checkpoint;
			expect(await verifyCheckpoint(forged, kp.publicKey)).toEqual({
				valid: false,
				reason: "unsupported_alg",
			});
		}
		expect(await verifyCheckpoint({ ...c, signature: "AAAA" }, kp.publicKey)).toMatchObject({
			valid: false,
		});
		expect(await verifyCheckpoint({} as Checkpoint, kp.publicKey)).toEqual({
			valid: false,
			reason: "malformed",
		});
	});

	it("verifies against a key set for rotation", async () => {
		await addN(db, 1, 2);
		const c = await cp();
		const next = await generateCheckpointKeyPair("k2");
		expect(await verifyCheckpoint(c, [next.publicKey, kp.publicKey])).toEqual({ valid: true });
		expect(await verifyCheckpoint(c, [next.publicKey])).toMatchObject({ reason: "unknown_key" });
	});

	it("proves inclusion in an older checkpoint after more rows arrive", async () => {
		await addN(db, 1, 5);
		const old = await cp();
		await addN(db, 6, 12);
		const p = await createInclusionProof(db, "r3", old);
		if (!p.success) throw new Error(p.error.message);
		expect(p.data.treeSize).toBe(5);
		expect(await verifyInclusionProof(p.data, old, kp.publicKey)).toEqual({ valid: true });
		const late = await createInclusionProof(db, "r9", old);
		expect(late).toMatchObject({ success: false, error: { code: "ROW_NOT_FOUND" } });
	});

	it("breaks ties between rows with the same timestamp by id", async () => {
		await add(db, "dup-b", "a1", 1);
		await add(db, "dup-a", "a2", 1);
		await add(db, "dup-c", "a1", 1);
		const c = await cp();
		expect(c.size).toBe(3);
		for (const id of ["dup-a", "dup-b", "dup-c"]) {
			const p = await createInclusionProof(db, id, c);
			if (!p.success) throw new Error(p.error.message);
			expect(await verifyInclusionProof(p.data, c, kp.publicKey)).toEqual({ valid: true });
		}
		const again = await cp();
		expect(again.rootHash).toBe(c.rootHash);
	});

	it("rejects an inclusion proof that is tampered or paired with another checkpoint", async () => {
		await addN(db, 1, 6);
		const c = await cp();
		const p = await createInclusionProof(db, "r2", c);
		if (!p.success) throw new Error(p.error.message);
		const proof = p.data;
		const flipHex = (h: string) => (h[0] === "a" ? "b" : "a") + h.slice(1);
		expect(
			await verifyInclusionProof({ ...proof, leafHash: flipHex(proof.leafHash) }, c, kp.publicKey),
		).toMatchObject({ valid: false, reason: "bad_proof" });
		expect(await verifyInclusionProof({ ...proof, leafIndex: 3 }, c, kp.publicKey)).toMatchObject({
			valid: false,
		});
		expect(
			await verifyInclusionProof({ ...proof, path: proof.path.slice(1) }, c, kp.publicKey),
		).toMatchObject({ valid: false });
		expect(await verifyInclusionProof({ ...proof, treeSize: 7 }, c, kp.publicKey)).toEqual({
			valid: false,
			reason: "size_mismatch",
		});
		expect(await verifyInclusionProof({ ...proof, path: ["zz"] }, c, kp.publicKey)).toEqual({
			valid: false,
			reason: "malformed",
		});
		await addN(db, 7, 8);
		const newer = await cp();
		expect(await verifyInclusionProof(proof, newer, kp.publicKey)).toMatchObject({ valid: false });
		const other = await generateCheckpointKeyPair("k1");
		expect(await verifyInclusionProof(proof, c, other.publicKey)).toMatchObject({ valid: false });
	});

	it("refuses to prove anything once a covered row is edited or deleted", async () => {
		await addN(db, 1, 5);
		const c = await cp();
		await db.update(auditLogs).set({ action: "delete" }).where(eq(auditLogs.id, "r2"));
		expect(await createInclusionProof(db, "r4", c)).toMatchObject({
			success: false,
			error: { code: "LOG_MISMATCH" },
		});
		await db.update(auditLogs).set({ action: "execute" }).where(eq(auditLogs.id, "r2"));
		expect(await createInclusionProof(db, "r4", c)).toMatchObject({ success: true });
		await db.delete(auditLogs).where(eq(auditLogs.id, "r5"));
		expect(await createInclusionProof(db, "r1", c)).toMatchObject({
			success: false,
			error: { code: "LOG_MISMATCH" },
		});
	});

	it("proves a newer checkpoint extends an older one, and not after a rewrite", async () => {
		await addN(db, 1, 5);
		const old = await cp();
		await addN(db, 6, 13);
		const newer = await cp();
		const p = await createConsistencyProof(db, old, newer);
		if (!p.success) throw new Error(p.error.message);
		expect(await verifyConsistencyProof(p.data, old, newer, kp.publicKey)).toEqual({ valid: true });

		expect(
			await verifyConsistencyProof(
				{ ...p.data, path: p.data.path.slice(1) },
				old,
				newer,
				kp.publicKey,
			),
		).toMatchObject({ valid: false });
		expect(
			await verifyConsistencyProof({ ...p.data, oldSize: 4 }, old, newer, kp.publicKey),
		).toEqual({ valid: false, reason: "size_mismatch" });
		expect(await verifyConsistencyProof(p.data, newer, old, kp.publicKey)).toMatchObject({
			valid: false,
		});

		await db.update(auditLogs).set({ resource: "mcp:rewritten" }).where(eq(auditLogs.id, "r1"));
		const forged = await cp();
		expect(await createConsistencyProof(db, old, forged)).toMatchObject({
			success: false,
			error: { code: "LOG_MISMATCH" },
		});
		// A forged newer head cannot be made consistent with the old one.
		const honest = p.data;
		expect(await verifyConsistencyProof(honest, old, forged, kp.publicKey)).toMatchObject({
			valid: false,
		});
	});

	it("handles consistency with an empty or equal older checkpoint", async () => {
		const empty = await cp();
		await addN(db, 1, 3);
		const three = await cp();
		const p0 = await createConsistencyProof(db, empty, three);
		if (!p0.success) throw new Error(p0.error.message);
		expect(await verifyConsistencyProof(p0.data, empty, three, kp.publicKey)).toEqual({
			valid: true,
		});
		const same = await createConsistencyProof(db, three, three);
		if (!same.success) throw new Error(same.error.message);
		expect(await verifyConsistencyProof(same.data, three, three, kp.publicKey)).toEqual({
			valid: true,
		});
	});

	it("scopes a checkpoint with since", async () => {
		await addN(db, 1, 6);
		const scoped = await cp({ since: new Date(T0.getTime() + 4000) });
		expect(scoped.size).toBe(3);
		expect(scoped.since).toBe(T0.getTime() + 4000);
		expect(await createInclusionProof(db, "r1", scoped)).toMatchObject({ success: false });
		const p = await createInclusionProof(db, "r5", scoped);
		if (!p.success) throw new Error(p.error.message);
		expect(await verifyInclusionProof(p.data, scoped, kp.publicKey)).toEqual({ valid: true });
		expect(await verifyCheckpoint({ ...scoped, since: null }, kp.publicKey)).toMatchObject({
			valid: false,
		});
	});

	it("stores checkpoints", async () => {
		const store = createMemoryCheckpointStore();
		expect(await store.latest()).toBeUndefined();
		await addN(db, 1, 2);
		const a = await createCheckpoint(db, { signer: kp.signer, store });
		await addN(db, 3, 4);
		const b = await createCheckpoint(db, { signer: kp.signer, store });
		if (!a.success || !b.success) throw new Error("create failed");
		await store.put(b.data);
		expect((await store.list()).map((c) => c.size)).toEqual([2, 4]);
		expect((await store.latest())?.size).toBe(4);
		expect(await store.getBySize(2)).toHaveLength(1);
	});
});

describe("audit receipts", () => {
	let db: Database;
	let kp: Awaited<ReturnType<typeof generateCheckpointKeyPair>>;
	let checkpoint: Checkpoint;
	beforeEach(async () => {
		db = await setup();
		kp = await generateCheckpointKeyPair("k1");
		await addN(db, 1, 7);
		const r = await createCheckpoint(db, { signer: kp.signer });
		if (!r.success) throw new Error(r.error.message);
		checkpoint = r.data;
	});

	async function receipt(reveal: string[], rowId = "r3"): Promise<Receipt> {
		const r = await createReceipt(db, rowId, checkpoint, { reveal });
		if (!r.success) throw new Error(r.error.message);
		return r.data;
	}

	it("verifies a receipt that reveals only chosen fields", async () => {
		const r = await receipt(["action", "resource", "result", "timestamp"]);
		const wire = JSON.parse(JSON.stringify(r)) as Receipt;
		expect(await verifyReceipt(wire, kp.publicKey)).toEqual({ valid: true });
		expect(Object.keys(wire.decision.revealed).sort()).toEqual([
			"action",
			"resource",
			"result",
			"timestamp",
		]);
		expect(wire.decision.revealed.resource?.value).toBe("mcp:github:r3");
		expect(wire.decision.commitments.parameters).toMatch(/^[0-9a-f]{64}$/);
		expect(JSON.stringify(wire)).not.toContain("param-of-r3");
	});

	it("verifies with nothing revealed and with everything revealed", async () => {
		expect(await verifyReceipt(await receipt([]), kp.publicKey)).toEqual({ valid: true });
		const all = await receipt([
			"id",
			"action",
			"resource",
			"parameters",
			"result",
			"reason",
			"durationMs",
			"tokensCost",
			"ip",
			"userAgent",
			"cacheHit",
			"timestamp",
			"policyVersion",
			"delegationChain",
			"inputProvenance",
			"idPseudonyms",
		]);
		expect(await verifyReceipt(all, kp.publicKey)).toEqual({ valid: true });
		expect(all.decision.revealed.parameters?.value).toEqual({ secret: "param-of-r3" });
	});

	it("rejects a changed revealed value, a swapped salt and a changed commitment", async () => {
		const r = await receipt(["action", "result"]);
		const edited = structuredClone(r);
		(edited.decision.revealed.result as { value: unknown }).value = "denied";
		expect(await verifyReceipt(edited, kp.publicKey)).toEqual({
			valid: false,
			reason: "leaf_mismatch",
		});

		const salt = structuredClone(r);
		(salt.decision.revealed.action as { salt: string }).salt = "0".repeat(64);
		expect(await verifyReceipt(salt, kp.publicKey)).toEqual({
			valid: false,
			reason: "leaf_mismatch",
		});

		const commit = structuredClone(r);
		commit.decision.commitments.parameters = "0".repeat(64);
		expect(await verifyReceipt(commit, kp.publicKey)).toEqual({
			valid: false,
			reason: "leaf_mismatch",
		});

		const rowHash = structuredClone(r);
		rowHash.decision.rowHash = "0".repeat(64);
		expect(await verifyReceipt(rowHash, kp.publicKey)).toEqual({
			valid: false,
			reason: "leaf_mismatch",
		});
	});

	it("rejects hiding a field by dropping it, hiding salts as values, or moving a field between sets", async () => {
		const r = await receipt(["action"]);
		const dropped = structuredClone(r);
		Reflect.deleteProperty(dropped.decision.commitments, "parameters");
		expect(await verifyReceipt(dropped, kp.publicKey)).toEqual({
			valid: false,
			reason: "malformed",
		});

		const dup = structuredClone(r);
		dup.decision.commitments.action = "0".repeat(64);
		expect(await verifyReceipt(dup, kp.publicKey)).toEqual({ valid: false, reason: "malformed" });

		const extra = structuredClone(r);
		extra.decision.commitments.bogus = "0".repeat(64);
		expect(await verifyReceipt(extra, kp.publicKey)).toEqual({ valid: false, reason: "malformed" });
	});

	it("rejects a receipt with the wrong key, a forged checkpoint, or another row's proof", async () => {
		const r = await receipt(["action"]);
		const other = await generateCheckpointKeyPair("k1");
		expect(await verifyReceipt(r, other.publicKey)).toMatchObject({
			valid: false,
			reason: "bad_signature",
		});

		const forgedCp = structuredClone(r);
		forgedCp.checkpoint.rootHash = "1".repeat(64);
		expect(await verifyReceipt(forgedCp, kp.publicKey)).toMatchObject({ valid: false });

		const noneAlg = structuredClone(r) as unknown as { checkpoint: { alg: string } };
		noneAlg.checkpoint.alg = "none";
		expect(await verifyReceipt(noneAlg as unknown as Receipt, kp.publicKey)).toEqual({
			valid: false,
			reason: "unsupported_alg",
		});

		const r5 = await receipt(["action"], "r5");
		const mixed = structuredClone(r);
		mixed.proof = r5.proof;
		expect(await verifyReceipt(mixed, kp.publicKey)).toMatchObject({ valid: false });
		expect(await verifyReceipt({} as Receipt, kp.publicKey)).toEqual({
			valid: false,
			reason: "malformed",
		});
	});

	it("rejects unknown reveal fields and fields the row does not carry", async () => {
		expect(await createReceipt(db, "r3", checkpoint, { reveal: ["agentId"] })).toMatchObject({
			success: false,
			error: { code: "INVALID_FIELD" },
		});
		expect(await createReceipt(db, "r3", checkpoint, { reveal: ["nope"] })).toMatchObject({
			success: false,
			error: { code: "INVALID_FIELD" },
		});
		expect(await createReceipt(db, "missing", checkpoint, { reveal: [] })).toMatchObject({
			success: false,
			error: { code: "ROW_NOT_FOUND" },
		});
	});

	it("still verifies after rows are added and with an older checkpoint", async () => {
		const r = await receipt(["action"]);
		await addN(db, 8, 20);
		expect(await verifyReceipt(r, kp.publicKey)).toEqual({ valid: true });
		const again = await createReceipt(db, "r3", checkpoint, { reveal: ["action"] });
		expect(again.success).toBe(true);
	});

	it("does not mint a receipt for a tampered row", async () => {
		await db.update(auditLogs).set({ result: "denied" }).where(eq(auditLogs.id, "r3"));
		expect(await createReceipt(db, "r3", checkpoint, { reveal: ["result"] })).toMatchObject({
			success: false,
			error: { code: "LOG_MISMATCH" },
		});
	});
});
