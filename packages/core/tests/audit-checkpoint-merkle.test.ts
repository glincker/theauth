/** RFC 6962 Merkle tree: roots against an independent node:crypto reference, and every inclusion and consistency proof for tree sizes 1..33. */

import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
	consistencyPath,
	inclusionPath,
	merkleLeafHash,
	merkleNodeHash,
	merkleRoot,
	verifyConsistencyPath,
	verifyInclusionPath,
} from "../src/audit/checkpoint-merkle.js";
import { toHex } from "../src/crypto/web-crypto.js";

const MAX = 33;

function ref(bytes: Uint8Array): Uint8Array {
	return new Uint8Array(createHash("sha256").update(bytes).digest());
}

function cat(...parts: Uint8Array[]): Uint8Array {
	const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
	let at = 0;
	for (const p of parts) {
		out.set(p, at);
		at += p.length;
	}
	return out;
}

/** Straight transcription of the RFC 6962 definition, on raw data, with node:crypto. */
function refRoot(data: Uint8Array[]): Uint8Array {
	if (data.length === 0) return ref(new Uint8Array(0));
	if (data.length === 1) return ref(cat(new Uint8Array([0]), data[0] as Uint8Array));
	let k = 1;
	while (k * 2 < data.length) k *= 2;
	return ref(cat(new Uint8Array([1]), refRoot(data.slice(0, k)), refRoot(data.slice(k))));
}

function datum(i: number): Uint8Array {
	return new TextEncoder().encode(`leaf-${i}`);
}

async function leafHashes(n: number): Promise<Uint8Array[]> {
	const out: Uint8Array[] = [];
	for (let i = 0; i < n; i++) out.push(await merkleLeafHash(datum(i)));
	return out;
}

function flip(b: Uint8Array): Uint8Array {
	const c = new Uint8Array(b);
	c[0] = (c[0] as number) ^ 1;
	return c;
}

// Exhaustive proofs over every tree size hash a lot through WebCrypto. Shared CI runners need more than the 5s default.
const SLOW_TEST_TIMEOUT_MS = 60_000;

describe("merkle tree (RFC 6962)", () => {
	it("hashes the empty tree and a single empty leaf to the published values", async () => {
		expect(toHex(await merkleRoot([]))).toBe(
			"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		);
		const one = await merkleLeafHash(new Uint8Array(0));
		expect(toHex(one)).toBe("6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d");
	});

	it("domain separates leaves from nodes", async () => {
		const a = await merkleLeafHash(new Uint8Array([1]));
		const b = await merkleLeafHash(new Uint8Array([2]));
		const node = await merkleNodeHash(a, b);
		const asLeaf = await merkleLeafHash(cat(a, b));
		expect(toHex(node)).not.toBe(toHex(asLeaf));
	});

	it("matches the reference root for every size", async () => {
		for (let n = 0; n <= MAX; n++) {
			const data = Array.from({ length: n }, (_, i) => datum(i));
			expect(toHex(await merkleRoot(await leafHashes(n)))).toBe(toHex(refRoot(data)));
		}
	});

	it(
		"proves inclusion for every index of every size, and rejects tampering",
		async () => {
			for (let n = 1; n <= MAX; n++) {
				const leaves = await leafHashes(n);
				const root = await merkleRoot(leaves);
				for (let i = 0; i < n; i++) {
					const path = await inclusionPath(leaves, i);
					const leaf = leaves[i] as Uint8Array;
					expect(await verifyInclusionPath(leaf, i, n, path, root)).toBe(true);
					expect(await verifyInclusionPath(flip(leaf), i, n, path, root)).toBe(false);
					expect(await verifyInclusionPath(leaf, i, n, path, flip(root))).toBe(false);
					if (n > 1) {
						expect(await verifyInclusionPath(leaf, (i + 1) % n, n, path, root)).toBe(false);
					}
					for (let j = 0; j < path.length; j++) {
						const bad = path.map((p, k) => (k === j ? flip(p) : p));
						expect(await verifyInclusionPath(leaf, i, n, bad, root)).toBe(false);
					}
					if (path.length > 0) {
						expect(await verifyInclusionPath(leaf, i, n, path.slice(1), root)).toBe(false);
					}
					expect(await verifyInclusionPath(leaf, i, n, [...path, root], root)).toBe(false);
				}
			}
		},
		SLOW_TEST_TIMEOUT_MS,
	);

	it(
		"proves consistency for every old size of every size, and rejects tampering",
		async () => {
			for (let n = 1; n <= MAX; n++) {
				const leaves = await leafHashes(n);
				const newRoot = await merkleRoot(leaves);
				for (let m = 1; m <= n; m++) {
					const oldRoot = await merkleRoot(leaves.slice(0, m));
					const path = await consistencyPath(leaves, m);
					expect(await verifyConsistencyPath(m, n, oldRoot, newRoot, path)).toBe(true);
					expect(await verifyConsistencyPath(m, n, flip(oldRoot), newRoot, path)).toBe(false);
					expect(await verifyConsistencyPath(m, n, oldRoot, flip(newRoot), path)).toBe(false);
					for (let j = 0; j < path.length; j++) {
						const bad = path.map((p, k) => (k === j ? flip(p) : p));
						expect(await verifyConsistencyPath(m, n, oldRoot, newRoot, bad)).toBe(false);
					}
					if (path.length > 0) {
						expect(await verifyConsistencyPath(m, n, oldRoot, newRoot, path.slice(1))).toBe(false);
						expect(await verifyConsistencyPath(m, n, oldRoot, newRoot, path.slice(0, -1))).toBe(
							false,
						);
					}
					expect(await verifyConsistencyPath(m, n, oldRoot, newRoot, [...path, newRoot])).toBe(
						false,
					);
				}
			}
		},
		SLOW_TEST_TIMEOUT_MS,
	);

	it("rejects a rewritten history: same size, different early leaf", async () => {
		const leaves = await leafHashes(13);
		const forged = [...leaves];
		forged[2] = await merkleLeafHash(new TextEncoder().encode("rewritten"));
		const oldRoot = await merkleRoot(leaves.slice(0, 7));
		const path = await consistencyPath(forged, 7);
		expect(await verifyConsistencyPath(7, 13, oldRoot, await merkleRoot(forged), path)).toBe(false);
	});

	it("rejects bad sizes", async () => {
		const leaves = await leafHashes(5);
		const root = await merkleRoot(leaves);
		expect(await verifyConsistencyPath(6, 5, root, root, [])).toBe(false);
		expect(await verifyInclusionPath(leaves[0] as Uint8Array, 5, 5, [], root)).toBe(false);
		expect(await verifyInclusionPath(leaves[0] as Uint8Array, -1, 5, [], root)).toBe(false);
		await expect(inclusionPath(leaves, 5)).rejects.toThrow(RangeError);
		await expect(consistencyPath(leaves, 6)).rejects.toThrow(RangeError);
	});
});
