/**
 * Merkle tree hashing and proofs, RFC 6962 section 2.1 (Certificate
 * Transparency). Leaf hashes are SHA-256(0x00 || data), interior nodes are
 * SHA-256(0x01 || left || right), and the empty tree hashes the empty string.
 * The proof verification loops follow the iterative form in RFC 9162 section 2.1.
 *
 * Everything here works on raw 32 byte hashes. Callers hex-encode at the edges.
 */

import { constantTimeEqual, sha256Raw } from "../crypto/web-crypto.js";

const LEAF_PREFIX = 0x00;
const NODE_PREFIX = 0x01;
const HASH_BYTES = 32;

function prefixed(prefix: number, ...parts: Uint8Array[]): Uint8Array {
	let total = 1;
	for (const p of parts) total += p.length;
	const out = new Uint8Array(total);
	out[0] = prefix;
	let at = 1;
	for (const p of parts) {
		out.set(p, at);
		at += p.length;
	}
	return out;
}

/** RFC 6962 leaf hash: SHA-256(0x00 || data). */
export function merkleLeafHash(data: Uint8Array): Promise<Uint8Array> {
	return sha256Raw(prefixed(LEAF_PREFIX, data));
}

/** RFC 6962 interior node hash: SHA-256(0x01 || left || right). */
export function merkleNodeHash(left: Uint8Array, right: Uint8Array): Promise<Uint8Array> {
	return sha256Raw(prefixed(NODE_PREFIX, left, right));
}

function isPowerOfTwo(n: number): boolean {
	if (!Number.isSafeInteger(n) || n <= 0) return false;
	const big = BigInt(n);
	return (big & (big - 1n)) === 0n;
}

/** Hashes per Promise.all batch when building a level, so a large level does not queue millions of digests. */
const LEVEL_BATCH = 512;

/**
 * Every level of the tree, bottom up. Level 0 is the leaf array itself (not copied) and the
 * last level holds the root. An odd node at the end of a level is promoted unchanged, which
 * gives exactly the RFC 6962 tree (split at the largest power of two below n).
 */
async function buildLevels(leafHashes: readonly Uint8Array[]): Promise<Uint8Array[][]> {
	const levels: Uint8Array[][] = [leafHashes as Uint8Array[]];
	let current = leafHashes;
	while (current.length > 1) {
		const below = current;
		const pairs = Math.floor(below.length / 2);
		const next: Uint8Array[] = new Array(Math.ceil(below.length / 2));
		for (let from = 0; from < pairs; from += LEVEL_BATCH) {
			const to = Math.min(pairs, from + LEVEL_BATCH);
			const batch: Promise<Uint8Array>[] = [];
			for (let i = from; i < to; i++) {
				batch.push(merkleNodeHash(below[2 * i] as Uint8Array, below[2 * i + 1] as Uint8Array));
			}
			const done = await Promise.all(batch);
			for (let i = from; i < to; i++) next[i] = done[i - from] as Uint8Array;
		}
		if (below.length % 2 === 1) next[pairs] = below[below.length - 1] as Uint8Array;
		levels.push(next);
		current = next;
	}
	return levels;
}

function ceilLog2(n: number): number {
	let h = 0;
	let span = 1;
	while (span < n) {
		span *= 2;
		h++;
	}
	return h;
}

/** Largest power of two strictly less than n (n >= 2). */
function splitPoint(n: number): number {
	let k = 1;
	while (k * 2 < n) k *= 2;
	return k;
}

/** A tree whose levels are built once and reused for the root and every proof. */
export interface MerkleTree {
	readonly size: number;
	root(): Promise<Uint8Array>;
	/** Root of the tree over the first `count` leaves. */
	prefixRoot(count: number): Promise<Uint8Array>;
	inclusionPath(index: number): Promise<Uint8Array[]>;
	consistencyPath(oldSize: number): Promise<Uint8Array[]>;
}

/** Build the tree over already-hashed leaves (O(n) hashes, once). */
export async function buildMerkleTree(leafHashes: readonly Uint8Array[]): Promise<MerkleTree> {
	const n = leafHashes.length;
	const levels = n === 0 ? [] : await buildLevels(leafHashes);

	// Root of leaves [start, end). A stored node when the range is a full aligned subtree or
	// runs to the end of the tree, otherwise the RFC split.
	async function rangeRoot(start: number, end: number): Promise<Uint8Array> {
		const len = end - start;
		if (len <= 0) return sha256Raw(new Uint8Array(0));
		const h = ceilLog2(len);
		const aligned = start % 2 ** h === 0;
		if (aligned && (len === 2 ** h || end === n)) {
			const node = levels[h]?.[start / 2 ** h];
			if (node) return node;
		}
		const k = splitPoint(len);
		return merkleNodeHash(await rangeRoot(start, start + k), await rangeRoot(start + k, end));
	}

	async function subProof(
		m: number,
		start: number,
		end: number,
		complete: boolean,
	): Promise<Uint8Array[]> {
		const len = end - start;
		if (m === len) return complete ? [] : [await rangeRoot(start, end)];
		const k = splitPoint(len);
		if (m <= k) {
			const sub = await subProof(m, start, start + k, complete);
			sub.push(await rangeRoot(start + k, end));
			return sub;
		}
		const sub = await subProof(m - k, start + k, end, false);
		sub.push(await rangeRoot(start, start + k));
		return sub;
	}

	return {
		size: n,
		root: () => rangeRoot(0, n),
		prefixRoot: (count) => rangeRoot(0, count),
		inclusionPath(index) {
			if (!Number.isInteger(index) || index < 0 || index >= n) {
				return Promise.reject(new RangeError("inclusionPath: index out of range"));
			}
			const path: Uint8Array[] = [];
			let at = index;
			for (let level = 0; level < levels.length - 1; level++) {
				const row = levels[level] as Uint8Array[];
				const sibling = row[at ^ 1];
				if (sibling) path.push(sibling);
				at = Math.floor(at / 2);
			}
			return Promise.resolve(path);
		},
		async consistencyPath(oldSize) {
			if (!Number.isInteger(oldSize) || oldSize < 0 || oldSize > n) {
				throw new RangeError("consistencyPath: oldSize out of range");
			}
			if (oldSize === 0 || oldSize === n) return [];
			return subProof(oldSize, 0, n, true);
		},
	};
}

/** Merkle tree hash over already-hashed leaves. The empty tree is SHA-256 of the empty string. */
export async function merkleRoot(leafHashes: readonly Uint8Array[]): Promise<Uint8Array> {
	return (await buildMerkleTree(leafHashes)).root();
}

/** Audit path for the leaf at `index` in a tree of `leafHashes` (RFC 6962 PATH). */
export async function inclusionPath(
	leafHashes: readonly Uint8Array[],
	index: number,
): Promise<Uint8Array[]> {
	const n = leafHashes.length;
	if (!Number.isInteger(index) || index < 0 || index >= n) {
		throw new RangeError("inclusionPath: index out of range");
	}
	return (await buildMerkleTree(leafHashes)).inclusionPath(index);
}

/**
 * Consistency proof between the tree of the first `oldSize` leaves and the
 * tree of all `leafHashes` (RFC 6962 PROOF). Empty when oldSize is 0 or equals
 * the full size.
 */
export async function consistencyPath(
	leafHashes: readonly Uint8Array[],
	oldSize: number,
): Promise<Uint8Array[]> {
	const n = leafHashes.length;
	if (!Number.isInteger(oldSize) || oldSize < 0 || oldSize > n) {
		throw new RangeError("consistencyPath: oldSize out of range");
	}
	if (oldSize === 0 || oldSize === n) return [];
	return (await buildMerkleTree(leafHashes)).consistencyPath(oldSize);
}

/** Recompute the root from a leaf hash and its audit path. Returns undefined when the path shape is wrong. */
export async function rootFromInclusion(
	leafHash: Uint8Array,
	index: number,
	size: number,
	path: readonly Uint8Array[],
): Promise<Uint8Array | undefined> {
	if (!Number.isInteger(index) || !Number.isInteger(size) || index < 0 || index >= size) {
		return undefined;
	}
	let fn = index;
	let sn = size - 1;
	let r = leafHash;
	for (const p of path) {
		if (sn === 0) return undefined;
		if ((fn & 1) === 1 || fn === sn) {
			r = await merkleNodeHash(p, r);
			if ((fn & 1) === 0) {
				while ((fn & 1) === 0 && fn !== 0) {
					fn = Math.floor(fn / 2);
					sn = Math.floor(sn / 2);
				}
			}
		} else {
			r = await merkleNodeHash(r, p);
		}
		fn = Math.floor(fn / 2);
		sn = Math.floor(sn / 2);
	}
	return sn === 0 ? r : undefined;
}

/** True when `path` proves the leaf at `index` is in the tree of `size` leaves with root `root`. */
export async function verifyInclusionPath(
	leafHash: Uint8Array,
	index: number,
	size: number,
	path: readonly Uint8Array[],
	root: Uint8Array,
): Promise<boolean> {
	if (leafHash.length !== HASH_BYTES || root.length !== HASH_BYTES) return false;
	if (path.some((p) => p.length !== HASH_BYTES)) return false;
	const computed = await rootFromInclusion(leafHash, index, size, path);
	return computed !== undefined && constantTimeEqual(computed, root);
}

/**
 * True when `path` proves the tree of `newSize` leaves (root `newRoot`) extends
 * the tree of `oldSize` leaves (root `oldRoot`) without changing any old leaf.
 */
export async function verifyConsistencyPath(
	oldSize: number,
	newSize: number,
	oldRoot: Uint8Array,
	newRoot: Uint8Array,
	path: readonly Uint8Array[],
): Promise<boolean> {
	if (!Number.isInteger(oldSize) || !Number.isInteger(newSize)) return false;
	if (oldSize < 0 || oldSize > newSize) return false;
	if (oldRoot.length !== HASH_BYTES || newRoot.length !== HASH_BYTES) return false;
	if (path.some((p) => p.length !== HASH_BYTES)) return false;
	if (oldSize === newSize) return path.length === 0 && constantTimeEqual(oldRoot, newRoot);
	if (oldSize === 0) {
		// The empty prefix has exactly one root: SHA-256 of the empty string.
		return path.length === 0 && constantTimeEqual(oldRoot, await sha256Raw(new Uint8Array(0)));
	}

	const nodes: Uint8Array[] = isPowerOfTwo(oldSize) ? [oldRoot, ...path] : [...path];
	const seed = nodes[0];
	if (!seed) return false;
	let fn = oldSize - 1;
	let sn = newSize - 1;
	while ((fn & 1) === 1) {
		fn = Math.floor(fn / 2);
		sn = Math.floor(sn / 2);
	}
	let fr = seed;
	let sr = seed;
	for (const c of nodes.slice(1)) {
		if (sn === 0) return false;
		if ((fn & 1) === 1 || fn === sn) {
			fr = await merkleNodeHash(c, fr);
			sr = await merkleNodeHash(c, sr);
			if ((fn & 1) === 0) {
				while ((fn & 1) === 0 && fn !== 0) {
					fn = Math.floor(fn / 2);
					sn = Math.floor(sn / 2);
				}
			}
		} else {
			sr = await merkleNodeHash(sr, c);
		}
		fn = Math.floor(fn / 2);
		sn = Math.floor(sn / 2);
	}
	return sn === 0 && constantTimeEqual(fr, oldRoot) && constantTimeEqual(sr, newRoot);
}
