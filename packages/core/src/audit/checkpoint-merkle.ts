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

/** Largest power of two strictly less than n (n >= 2). */
function splitPoint(n: number): number {
	let k = 1;
	while (k * 2 < n) k *= 2;
	return k;
}

function isPowerOfTwo(n: number): boolean {
	return n > 0 && (n & (n - 1)) === 0;
}

/** Merkle tree hash over already-hashed leaves. The empty tree is SHA-256 of the empty string. */
export async function merkleRoot(leafHashes: readonly Uint8Array[]): Promise<Uint8Array> {
	const n = leafHashes.length;
	if (n === 0) return sha256Raw(new Uint8Array(0));
	const first = leafHashes[0];
	if (n === 1 && first) return first;
	const k = splitPoint(n);
	const left = await merkleRoot(leafHashes.slice(0, k));
	const right = await merkleRoot(leafHashes.slice(k));
	return merkleNodeHash(left, right);
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
	if (n === 1) return [];
	const k = splitPoint(n);
	if (index < k) {
		const sub = await inclusionPath(leafHashes.slice(0, k), index);
		sub.push(await merkleRoot(leafHashes.slice(k)));
		return sub;
	}
	const sub = await inclusionPath(leafHashes.slice(k), index - k);
	sub.push(await merkleRoot(leafHashes.slice(0, k)));
	return sub;
}

async function subProof(
	m: number,
	leafHashes: readonly Uint8Array[],
	complete: boolean,
): Promise<Uint8Array[]> {
	const n = leafHashes.length;
	if (m === n) return complete ? [] : [await merkleRoot(leafHashes)];
	const k = splitPoint(n);
	if (m <= k) {
		const sub = await subProof(m, leafHashes.slice(0, k), complete);
		sub.push(await merkleRoot(leafHashes.slice(k)));
		return sub;
	}
	const sub = await subProof(m - k, leafHashes.slice(k), false);
	sub.push(await merkleRoot(leafHashes.slice(0, k)));
	return sub;
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
	return subProof(oldSize, leafHashes, true);
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
	if (oldSize === 0) return path.length === 0;

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
