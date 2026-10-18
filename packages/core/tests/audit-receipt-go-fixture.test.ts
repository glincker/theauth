/**
 * Verifies the vendored Go receipt fixture (tests/fixtures/receipts/go-fixture.json, written by
 * theauth-go) with the TypeScript checkpoint, inclusion, consistency and receipt verifiers.
 * Proves the Merkle and receipt layer interoperates; the row hash chains are separate formats.
 */

import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { verifyConsistencyProof, verifyInclusionProof } from "../src/audit/checkpoint.js";
import { verifyReceipt } from "../src/audit/checkpoint-receipt.js";
import { verifyCheckpoint } from "../src/audit/checkpoint-sign.js";
import type {
	Checkpoint,
	CheckpointPublicKey,
	ConsistencyProof,
	InclusionProof,
	Receipt,
	VerifyOutcome,
} from "../src/audit/checkpoint-types.js";

interface NegativeCase {
	name: string;
	kind: "checkpoint" | "inclusion" | "consistency" | "receipt";
	checkpoint: Checkpoint;
	proof: InclusionProof & ConsistencyProof;
	older: Checkpoint;
	newer: Checkpoint;
	receipt: Receipt;
	keys: CheckpointPublicKey[];
	expectedReason: string;
}

interface GoFixture {
	publicKeys: CheckpointPublicKey[];
	checkpoints: Record<string, Checkpoint>;
	inclusion: Array<{ proof: InclusionProof; checkpoint: Checkpoint }>;
	consistency: { proof: ConsistencyProof; older: Checkpoint; newer: Checkpoint };
	receipts: Array<{ name: string; receipt: Receipt }>;
	negative: NegativeCase[];
}

function load(): GoFixture {
	const url = new URL("./fixtures/receipts/go-fixture.json", import.meta.url);
	return JSON.parse(readFileSync(url, "utf8")) as GoFixture;
}

function clone<T>(value: T): T {
	return JSON.parse(JSON.stringify(value)) as T;
}

/** Flip the last hex digit, a one-nibble change that keeps the string well formed. */
function flipHex(hex: string): string {
	const last = hex.slice(-1);
	return hex.slice(0, -1) + (last === "0" ? "1" : "0");
}

function run(n: NegativeCase): Promise<VerifyOutcome> {
	switch (n.kind) {
		case "checkpoint":
			return verifyCheckpoint(n.checkpoint, n.keys);
		case "inclusion":
			return verifyInclusionProof(n.proof, n.checkpoint, n.keys);
		case "consistency":
			return verifyConsistencyProof(n.proof, n.older, n.newer, n.keys);
		default:
			return verifyReceipt(n.receipt, n.keys);
	}
}

describe("Go receipt fixture verifies with the TypeScript verifiers", () => {
	const fx = load();

	it("has the expected shape", () => {
		expect(fx.publicKeys.length).toBeGreaterThan(0);
		expect(fx.inclusion.length).toBeGreaterThan(0);
		expect(fx.receipts.length).toBeGreaterThan(0);
		expect(fx.negative.length).toBeGreaterThan(0);
	});

	it("verifies every checkpoint signature", async () => {
		for (const cp of Object.values(fx.checkpoints)) {
			expect(await verifyCheckpoint(cp, fx.publicKeys)).toEqual({ valid: true });
		}
	});

	it.each(
		load().inclusion.map((x, i) => [i, x] as const),
	)("verifies inclusion proof %i", async (_i, x) => {
		expect(await verifyInclusionProof(x.proof, x.checkpoint, fx.publicKeys)).toEqual({
			valid: true,
		});
	});

	it("verifies the consistency proof", async () => {
		const c = fx.consistency;
		expect(await verifyConsistencyProof(c.proof, c.older, c.newer, fx.publicKeys)).toEqual({
			valid: true,
		});
	});

	it.each(
		load().receipts.map((r) => [r.name, r.receipt] as const),
	)("verifies receipt %s", async (_name, receipt) => {
		expect(await verifyReceipt(receipt, fx.publicKeys)).toEqual({ valid: true });
	});

	it.each(
		load().negative.map((n) => [n.name, n] as const),
	)("rejects Go tamper case %s with the recorded reason", async (_name, n) => {
		expect(await run(n)).toEqual({ valid: false, reason: n.expectedReason });
	});
});

describe("one-byte mutations of the Go fixture are rejected", () => {
	const fx = load();
	const first = fx.inclusion[3] as GoFixture["inclusion"][number];

	it("flipped proof path digest", async () => {
		const proof = clone(first.proof);
		proof.path[0] = flipHex(proof.path[0] as string);
		expect((await verifyInclusionProof(proof, first.checkpoint, fx.publicKeys)).valid).toBe(false);
	});

	it("flipped root hash (signature no longer matches)", async () => {
		const cp = clone(first.checkpoint);
		cp.rootHash = flipHex(cp.rootHash);
		expect((await verifyInclusionProof(first.proof, cp, fx.publicKeys)).valid).toBe(false);
		expect((await verifyCheckpoint(cp, fx.publicKeys)).valid).toBe(false);
	});

	it("flipped leaf hash", async () => {
		const proof = clone(first.proof);
		proof.leafHash = flipHex(proof.leafHash);
		expect((await verifyInclusionProof(proof, first.checkpoint, fx.publicKeys)).valid).toBe(false);
	});

	it("changed leaf index", async () => {
		const proof = clone(first.proof);
		proof.leafIndex = proof.leafIndex + 1;
		expect((await verifyInclusionProof(proof, first.checkpoint, fx.publicKeys)).valid).toBe(false);
	});

	it("flipped signature byte", async () => {
		const cp = clone(first.checkpoint);
		const sig = cp.signature;
		cp.signature = (sig.startsWith("A") ? "B" : "A") + sig.slice(1);
		expect((await verifyCheckpoint(cp, fx.publicKeys)).valid).toBe(false);
	});

	it("receipt: flipped row hash, commitment, proof leaf and revealed salt", async () => {
		const base = fx.receipts[0] as GoFixture["receipts"][number];
		const a = clone(base.receipt);
		a.decision.rowHash = flipHex(a.decision.rowHash);
		const b = clone(base.receipt);
		const commitKey = Object.keys(b.decision.commitments)[0] as string;
		b.decision.commitments[commitKey] = flipHex(b.decision.commitments[commitKey] as string);
		const c = clone(base.receipt);
		c.proof.leafHash = flipHex(c.proof.leafHash);
		const d = clone(base.receipt);
		const revealedKey = Object.keys(d.decision.revealed)[0] as string;
		const field = d.decision.revealed[revealedKey] as { salt: string };
		field.salt = flipHex(field.salt);
		for (const r of [a, b, c, d]) {
			expect((await verifyReceipt(r, fx.publicKeys)).valid).toBe(false);
		}
	});
});
