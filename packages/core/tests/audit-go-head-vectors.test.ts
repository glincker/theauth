/**
 * Verifies the Go head checkpoint vectors (tests/fixtures/go-head-checkpoint-vectors.json), written
 * by the real theauth-go code (see scripts/go-head-vectors). Every expected result comes from the Go
 * VerifyHeadCheckpoint and CheckHeadCheckpoint, so a mismatch here is a cross language bug.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import type { CheckpointPublicKey } from "../src/audit/checkpoint-types.js";
import type { GoHeadCheckpoint, GoHeadRow } from "../src/audit/go-head-verify.js";
import {
	isWellFormedGoHead,
	verifyGoHeadCheckpoint,
	verifyGoHeadSignature,
} from "../src/audit/go-head-verify.js";

interface Case {
	name: string;
	mode: "signature" | "live";
	head: GoHeadCheckpoint;
	rows?: GoHeadRow[];
	keys: CheckpointPublicKey[];
	expected: { valid: boolean; reason?: string; chainKey?: string };
}

const vectors = JSON.parse(
	readFileSync(
		fileURLToPath(new URL("./fixtures/go-head-checkpoint-vectors.json", import.meta.url)),
		"utf8",
	),
) as { keyId: string; cases: Case[] };

const byName = (name: string): Case => {
	const c = vectors.cases.find((x) => x.name === name);
	if (!c) throw new Error(`missing vector ${name}`);
	return c;
};

describe("Go head checkpoint vectors", () => {
	it("has the cases the Go generator writes", () => {
		expect(vectors.cases.length).toBeGreaterThanOrEqual(25);
		const reasons = new Set(vectors.cases.map((c) => c.expected.reason));
		for (const r of ["chain_truncated", "head_mismatch", "bad_signature", "unknown_key"]) {
			expect(reasons.has(r)).toBe(true);
		}
	});

	for (const c of vectors.cases) {
		it(`${c.mode} ${c.name}`, async () => {
			const r =
				c.mode === "live"
					? await verifyGoHeadCheckpoint(c.head, c.keys, c.rows ?? [])
					: await verifyGoHeadSignature(c.head, c.keys);
			expect(r.valid).toBe(c.expected.valid);
			if (!r.valid) {
				expect(r.reason).toBe(c.expected.reason);
				if (c.expected.reason === "chain_truncated" || c.expected.reason === "head_mismatch") {
					expect(r.chainKey ?? "").toBe(c.expected.chainKey ?? "");
				}
			}
		});
	}

	it("treats a missing rows argument as a signature only check", async () => {
		const c = byName("chain_truncated_tail_cut");
		expect((await verifyGoHeadCheckpoint(c.head, c.keys)).valid).toBe(true);
		expect((await verifyGoHeadCheckpoint(c.head, c.keys, c.rows)).valid).toBe(false);
	});

	it("accepts a single key object as well as a list", async () => {
		const c = byName("ok_three_chains");
		expect((await verifyGoHeadSignature(c.head, c.keys[0] as CheckpointPublicKey)).valid).toBe(
			true,
		);
	});

	it("fails closed on hostile input instead of throwing", async () => {
		const k = byName("ok_three_chains").keys;
		for (const bad of [null, undefined, 7, "x", [], {}, { version: 1 }]) {
			const r = await verifyGoHeadSignature(bad, k);
			expect(r).toEqual({ valid: false, reason: "malformed" });
		}
		const c = byName("ok_three_chains");
		const noPad = { ...c.head, signature: `${c.head.signature}=` };
		expect(await verifyGoHeadSignature(noPad, c.keys)).toEqual({
			valid: false,
			reason: "bad_signature",
		});
		const nullKey = await verifyGoHeadSignature(c.head, [null as unknown as CheckpointPublicKey]);
		expect(nullKey).toEqual({ valid: false, reason: "unknown_key" });
	});

	it("rejects two rows that claim the signed seq with different hashes", async () => {
		const c = byName("ok_three_chains");
		const rows = [...(c.rows ?? [])];
		const first = rows[0] as GoHeadRow;
		const twin: GoHeadRow = { ...first, hash: "f".repeat(64) };
		const r = await verifyGoHeadCheckpoint(c.head, c.keys, [...rows, twin]);
		// seq 1 is not the signed seq of the global chain (3), so this stays valid.
		expect(r.valid).toBe(true);
		const last = rows.find((x) => x.chainSeq === 3 && (x.organizationId ?? "") === "") as GoHeadRow;
		const dup = await verifyGoHeadCheckpoint(c.head, c.keys, [
			...rows,
			{ ...last, hash: "f".repeat(64) },
		]);
		expect(dup).toEqual({ valid: false, reason: "head_mismatch", chainKey: "" });
	});

	it("skips unchained rows and accepts uppercase row hashes", async () => {
		const c = byName("ok_three_chains");
		const rows: GoHeadRow[] = (c.rows ?? []).map((r) => ({
			...r,
			hash: (r.hash ?? "").toUpperCase(),
		}));
		rows.push({ organizationId: null, chainSeq: 0, hash: "" }, { hash: null });
		expect((await verifyGoHeadCheckpoint(c.head, c.keys, rows)).valid).toBe(true);
	});

	it("shape check matches the Go rules", () => {
		const c = byName("ok_three_chains");
		expect(isWellFormedGoHead(c.head)).toBe(true);
		expect(isWellFormedGoHead({ ...c.head, heads: null })).toBe(false);
		expect(isWellFormedGoHead({ ...c.head, timestamp: 1.5 })).toBe(false);
		expect(isWellFormedGoHead({ ...c.head, timestamp: -1 })).toBe(false);
	});
});

describe("Ed25519 reference (RFC 8032 section 7.1 test 1)", () => {
	it("the vector key is the RFC public key", () => {
		const x = byName("ok_three_chains").keys[0]?.publicKey.x as string;
		const bytes = Uint8Array.from(Buffer.from(x, "base64url"));
		const hex = Buffer.from(bytes).toString("hex");
		expect(hex).toBe("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
	});

	it("Web Crypto verifies the RFC signature of the empty message", async () => {
		const pub = Buffer.from(
			"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
			"hex",
		);
		const sig = Buffer.from(
			"e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
			"hex",
		);
		const key = await crypto.subtle.importKey("raw", pub, { name: "Ed25519" }, false, ["verify"]);
		expect(await crypto.subtle.verify({ name: "Ed25519" }, key, sig, new Uint8Array(0))).toBe(true);
	});
});
