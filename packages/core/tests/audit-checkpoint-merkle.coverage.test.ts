/** Argument checks and rejection paths of the RFC 6962 Merkle helpers. */

import { describe, expect, it } from "vitest";
import {
	buildMerkleTree,
	consistencyPath,
	inclusionPath,
	merkleLeafHash,
	merkleRoot,
	rootFromInclusion,
	verifyConsistencyPath,
	verifyInclusionPath,
} from "../src/audit/checkpoint-merkle.js";
import { bytesToHex } from "../src/audit/checkpoint-sign.js";

const EMPTY_ROOT = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

async function leaves(n: number): Promise<Uint8Array[]> {
	const out: Uint8Array[] = [];
	for (let i = 0; i < n; i++) {
		out.push(await merkleLeafHash(new TextEncoder().encode(`leaf-${i}`)));
	}
	return out;
}

describe("merkle tree argument checks", () => {
	it("rejects inclusion paths for indexes outside the tree", async () => {
		const tree = await buildMerkleTree(await leaves(4));
		await expect(tree.inclusionPath(-1)).rejects.toThrow(RangeError);
		await expect(tree.inclusionPath(4)).rejects.toThrow(RangeError);
		await expect(tree.inclusionPath(1.5)).rejects.toThrow(RangeError);
	});

	it("rejects consistency paths for an old size outside the tree", async () => {
		const tree = await buildMerkleTree(await leaves(4));
		await expect(tree.consistencyPath(-1)).rejects.toThrow(RangeError);
		await expect(tree.consistencyPath(5)).rejects.toThrow(RangeError);
		await expect(tree.consistencyPath(0.5)).rejects.toThrow(RangeError);
	});

	it("applies the same checks to the standalone path helpers", async () => {
		const hashes = await leaves(3);
		await expect(inclusionPath(hashes, 3)).rejects.toThrow(RangeError);
		await expect(consistencyPath(hashes, -1)).rejects.toThrow(RangeError);
		expect(await consistencyPath(hashes, 0)).toEqual([]);
		expect(await consistencyPath(hashes, 3)).toEqual([]);
	});

	it("hashes the empty tree to SHA-256 of the empty string", async () => {
		expect(bytesToHex(await merkleRoot([]))).toBe(EMPTY_ROOT);
	});
});

describe("verifyConsistencyPath", () => {
	it("accepts a genuine proof and rejects it for a different new root", async () => {
		const hashes = await leaves(7);
		const oldRoot = await (await buildMerkleTree(hashes.slice(0, 3))).root();
		const newTree = await buildMerkleTree(hashes);
		const newRoot = await newTree.root();
		const path = await newTree.consistencyPath(3);
		expect(await verifyConsistencyPath(3, 7, oldRoot, newRoot, path)).toBe(true);
		expect(await verifyConsistencyPath(3, 7, oldRoot, oldRoot, path)).toBe(false);
	});

	it("rejects sizes that are not integers or that shrink", async () => {
		const root = await merkleRoot(await leaves(2));
		expect(await verifyConsistencyPath(1.5, 2, root, root, [])).toBe(false);
		expect(await verifyConsistencyPath(2, 1, root, root, [])).toBe(false);
	});

	it("rejects roots and path entries that are not 32 bytes", async () => {
		const root = await merkleRoot(await leaves(2));
		const short = new Uint8Array(31);
		expect(await verifyConsistencyPath(1, 2, short, root, [])).toBe(false);
		expect(await verifyConsistencyPath(1, 2, root, short, [])).toBe(false);
		expect(await verifyConsistencyPath(1, 2, root, root, [short])).toBe(false);
	});

	it("requires an empty path when the sizes are equal, and matching roots", async () => {
		const root = await merkleRoot(await leaves(4));
		expect(await verifyConsistencyPath(4, 4, root, root, [])).toBe(true);
		expect(await verifyConsistencyPath(4, 4, root, root, [root])).toBe(false);
	});

	it("handles an empty old tree: no path and the empty-string root only", async () => {
		const empty = await merkleRoot([]);
		const root = await merkleRoot(await leaves(2));
		expect(await verifyConsistencyPath(0, 2, empty, root, [])).toBe(true);
		expect(await verifyConsistencyPath(0, 2, root, root, [])).toBe(false);
		expect(await verifyConsistencyPath(0, 2, empty, root, [empty])).toBe(false);
	});

	it("rejects an empty path when the old size is not a power of two", async () => {
		const oldRoot = await merkleRoot(await leaves(3));
		const newRoot = await merkleRoot(await leaves(5));
		expect(await verifyConsistencyPath(3, 5, oldRoot, newRoot, [])).toBe(false);
	});
});

describe("verifyInclusionPath and rootFromInclusion", () => {
	it("accepts a genuine path and rejects a wrong index or wrong sizes", async () => {
		const hashes = await leaves(5);
		const tree = await buildMerkleTree(hashes);
		const root = await tree.root();
		const path = await tree.inclusionPath(2);
		expect(await verifyInclusionPath(hashes[2] as Uint8Array, 2, 5, path, root)).toBe(true);
		expect(await verifyInclusionPath(hashes[2] as Uint8Array, 3, 5, path, root)).toBe(false);
	});

	it("rejects leaf, root and path entries that are not 32 bytes", async () => {
		const hashes = await leaves(2);
		const root = await merkleRoot(hashes);
		const short = new Uint8Array(8);
		expect(await verifyInclusionPath(short, 0, 2, [hashes[1] as Uint8Array], root)).toBe(false);
		expect(
			await verifyInclusionPath(hashes[0] as Uint8Array, 0, 2, [hashes[1] as Uint8Array], short),
		).toBe(false);
		expect(await verifyInclusionPath(hashes[0] as Uint8Array, 0, 2, [short], root)).toBe(false);
	});

	it("returns undefined from rootFromInclusion for an out-of-range index or a path that is too long", async () => {
		const hashes = await leaves(2);
		const leaf = hashes[0] as Uint8Array;
		const sibling = hashes[1] as Uint8Array;
		expect(await rootFromInclusion(leaf, 2, 2, [sibling])).toBeUndefined();
		expect(await rootFromInclusion(leaf, 0, 1.5, [])).toBeUndefined();
		expect(await rootFromInclusion(leaf, 0, 1, [sibling])).toBeUndefined();
		expect(await rootFromInclusion(leaf, 0, 2, [sibling])).toBeDefined();
	});
});
