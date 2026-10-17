/**
 * Signed audit checkpoints (a transparency-log style signed tree head) with inclusion and consistency proofs. See docs/audit-checkpoints.mdx.
 * Shape follows RFC 6962 (Certificate Transparency): a Merkle tree over the chained audit rows, a signed tree head, audit paths and consistency proofs.
 */

import { constantTimeEqual } from "../crypto/web-crypto.js";
import type { Database } from "../db/database.js";
import type { Result } from "../mcp/types.js";
import type { LeafSet } from "./checkpoint-leaves.js";
import { loadLeafSet } from "./checkpoint-leaves.js";
import type { MerkleTree } from "./checkpoint-merkle.js";
import {
	buildMerkleTree,
	verifyConsistencyPath,
	verifyInclusionPath,
} from "./checkpoint-merkle.js";
import {
	bytesToHex,
	hexToBytes,
	isHashHex,
	isWellFormedCheckpoint,
	signCheckpoint,
	verifyCheckpoint,
} from "./checkpoint-sign.js";
import type {
	Checkpoint,
	CheckpointPublicKey,
	CheckpointSigner,
	CheckpointStore,
	ConsistencyProof,
	InclusionProof,
	VerifyOutcome,
} from "./checkpoint-types.js";

export {
	createEd25519Signer,
	generateCheckpointKeyPair,
	verifyCheckpoint,
} from "./checkpoint-sign.js";

export interface CreateCheckpointOptions {
	signer: CheckpointSigner;
	/** Only cover rows with timestamp at or after this. Recorded (and signed) in the checkpoint. */
	since?: Date;
	/** Only cover rows with timestamp at or before this. Use it to leave out rows that may still be arriving. */
	until?: Date;
	/** Override the clock (tests). */
	now?: Date;
	/** Persist the checkpoint here after signing. */
	store?: CheckpointStore;
	/** Audit key for receipt salts. Defaults to `audit.hmacKey` of this database, else the installation secret. */
	hmacKey?: string;
}

export interface ProofOptions {
	hmacKey?: string;
}

function fail<T>(code: string, message: string): Result<T> {
	return { success: false, error: { code, message } };
}

function errMessage(err: unknown): string {
	return err instanceof Error ? err.message : "Unknown";
}

function rangeOf(cp: Checkpoint): { since: number | null; until: number | null } {
	return { since: cp.since, until: cp.until };
}

/** The leaves of a checkpointed log range and the tree built over them once. */
export interface CheckpointTree extends LeafSet {
	tree: MerkleTree;
}

async function treeOf(set: LeafSet): Promise<CheckpointTree> {
	return { ...set, tree: await buildMerkleTree(set.hashes) };
}

function same(a: string, b: string): boolean {
	if (!isHashHex(a) || !isHashHex(b)) return false;
	return constantTimeEqual(hexToBytes(a), hexToBytes(b));
}

/** Build a Merkle tree over every chained audit row and sign its head. An empty log gives a size 0 checkpoint. */
export async function createCheckpoint(
	db: Database,
	opts: CreateCheckpointOptions,
): Promise<Result<Checkpoint>> {
	try {
		const range = {
			since: opts.since ? opts.since.getTime() : null,
			until: opts.until ? opts.until.getTime() : null,
		};
		for (const bound of [range.since, range.until]) {
			if (bound !== null && !(Number.isSafeInteger(bound) && bound >= 0)) {
				return fail("INVALID_RANGE", "since and until must be valid dates at or after 1970");
			}
		}
		const timestamp = (opts.now ?? new Date()).getTime();
		if (!(Number.isSafeInteger(timestamp) && timestamp >= 0)) {
			return fail("INVALID_TIMESTAMP", "now must be a valid date at or after 1970");
		}
		const { ids, tree } = await treeOf(await loadLeafSet(db, range, opts.hmacKey));
		const checkpoint = await signCheckpoint(opts.signer, {
			version: 1,
			alg: "Ed25519",
			keyId: opts.signer.keyId,
			size: ids.length,
			rootHash: bytesToHex(await tree.root()),
			timestamp,
			...range,
		});
		if (opts.store) await opts.store.put(checkpoint);
		return { success: true, data: checkpoint };
	} catch (error) {
		return fail("CHECKPOINT_FAILED", errMessage(error));
	}
}

/**
 * Rebuild the first `checkpoint.size` leaves and confirm they still hash to the checkpoint root. A mismatch means the log was rewritten, shrunk, or a row landed inside the covered range after the checkpoint.
 */
async function leavesMatching(
	db: Database,
	checkpoint: Checkpoint,
	hmacKey?: string,
): Promise<Result<CheckpointTree>> {
	if (!isWellFormedCheckpoint(checkpoint))
		return fail("INVALID_CHECKPOINT", "Malformed checkpoint");
	const set = await loadLeafSet(db, rangeOf(checkpoint), hmacKey, checkpoint.size);
	if (set.ids.length < checkpoint.size) {
		return fail("LOG_MISMATCH", "The log has fewer rows than the checkpoint committed to");
	}
	const built = await treeOf(set);
	if (!same(bytesToHex(await built.tree.root()), checkpoint.rootHash)) {
		return fail("LOG_MISMATCH", "The log no longer matches the checkpoint root");
	}
	return { success: true, data: built };
}

export { leavesMatching as loadCheckpointTree };

/** Prove that a row is a leaf of the tree the checkpoint committed to. Later rows do not matter. */
export async function createInclusionProof(
	db: Database,
	rowId: string,
	checkpoint: Checkpoint,
	opts: ProofOptions = {},
): Promise<Result<InclusionProof>> {
	try {
		const leaves = await leavesMatching(db, checkpoint, opts.hmacKey);
		if (!leaves.success) return leaves;
		const { ids, hashes, tree } = leaves.data;
		const index = ids.indexOf(rowId);
		if (index < 0) return fail("ROW_NOT_FOUND", "The row is not covered by this checkpoint");
		const path = await tree.inclusionPath(index);
		return {
			success: true,
			data: {
				version: 1,
				rowId,
				leafIndex: index,
				treeSize: checkpoint.size,
				leafHash: bytesToHex(hashes[index] as Uint8Array),
				path: path.map(bytesToHex),
			},
		};
	} catch (error) {
		return fail("PROOF_FAILED", errMessage(error));
	}
}

function proofHexOk(proof: InclusionProof): boolean {
	return (
		proof.version === 1 &&
		typeof proof.rowId === "string" &&
		Number.isSafeInteger(proof.leafIndex) &&
		Number.isSafeInteger(proof.treeSize) &&
		isHashHex(proof.leafHash) &&
		Array.isArray(proof.path) &&
		proof.path.every(isHashHex)
	);
}

/** Offline check: the signed checkpoint is genuine and the proof's leaf hash is in its tree. */
export async function verifyInclusionProof(
	proof: InclusionProof,
	checkpoint: Checkpoint,
	publicKey: CheckpointPublicKey | readonly CheckpointPublicKey[],
): Promise<VerifyOutcome> {
	const signed = await verifyCheckpoint(checkpoint, publicKey);
	if (!signed.valid) return signed;
	if (typeof proof !== "object" || proof === null || !proofHexOk(proof)) {
		return { valid: false, reason: "malformed" };
	}
	if (proof.treeSize !== checkpoint.size) return { valid: false, reason: "size_mismatch" };
	try {
		const ok = await verifyInclusionPath(
			hexToBytes(proof.leafHash),
			proof.leafIndex,
			proof.treeSize,
			proof.path.map(hexToBytes),
			hexToBytes(checkpoint.rootHash),
		);
		return ok ? { valid: true } : { valid: false, reason: "bad_proof" };
	} catch {
		return { valid: false, reason: "malformed" };
	}
}

/**
 * Prove that `newer` extends `older` without rewriting any earlier row. Takes a database handle because the tree itself lives there; a checkpoint holds only the root. Fails if the log no longer matches either checkpoint.
 */
export async function createConsistencyProof(
	db: Database,
	older: Checkpoint,
	newer: Checkpoint,
	opts: ProofOptions = {},
): Promise<Result<ConsistencyProof>> {
	try {
		if (!isWellFormedCheckpoint(older) || !isWellFormedCheckpoint(newer)) {
			return fail("INVALID_CHECKPOINT", "Malformed checkpoint");
		}
		if (older.size > newer.size) {
			return fail("INVALID_ORDER", "The older checkpoint is larger than the newer one");
		}
		if (older.since !== newer.since) {
			return fail("SCOPE_MISMATCH", "The checkpoints cover different ranges");
		}
		const leaves = await leavesMatching(db, newer, opts.hmacKey);
		if (!leaves.success) return leaves;
		const oldRoot = bytesToHex(await leaves.data.tree.prefixRoot(older.size));
		if (!same(oldRoot, older.rootHash)) {
			return fail("LOG_MISMATCH", "The older checkpoint is not a prefix of the current log");
		}
		const path = await leaves.data.tree.consistencyPath(older.size);
		return {
			success: true,
			data: { version: 1, oldSize: older.size, newSize: newer.size, path: path.map(bytesToHex) },
		};
	} catch (error) {
		return fail("PROOF_FAILED", errMessage(error));
	}
}

/** Offline check that `newer` is an append-only extension of `older`. Both signatures are checked. */
export async function verifyConsistencyProof(
	proof: ConsistencyProof,
	older: Checkpoint,
	newer: Checkpoint,
	publicKey: CheckpointPublicKey | readonly CheckpointPublicKey[],
): Promise<VerifyOutcome> {
	const a = await verifyCheckpoint(older, publicKey);
	if (!a.valid) return a;
	const b = await verifyCheckpoint(newer, publicKey);
	if (!b.valid) return b;
	if (
		typeof proof !== "object" ||
		proof === null ||
		proof.version !== 1 ||
		!Array.isArray(proof.path) ||
		!proof.path.every(isHashHex)
	) {
		return { valid: false, reason: "malformed" };
	}
	if (proof.oldSize !== older.size || proof.newSize !== newer.size) {
		return { valid: false, reason: "size_mismatch" };
	}
	if (older.since !== newer.since) return { valid: false, reason: "scope_mismatch" };
	try {
		const ok = await verifyConsistencyPath(
			older.size,
			newer.size,
			hexToBytes(older.rootHash),
			hexToBytes(newer.rootHash),
			proof.path.map(hexToBytes),
		);
		return ok ? { valid: true } : { valid: false, reason: "bad_proof" };
	} catch {
		return { valid: false, reason: "malformed" };
	}
}
