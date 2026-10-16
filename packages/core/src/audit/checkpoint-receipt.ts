/**
 * Portable receipts: one JSON object holding a decision (with only the fields
 * the caller chose to reveal), an inclusion proof and the signed checkpoint.
 * A counterparty verifies it offline with the operator's public key.
 */

import { constantTimeEqual } from "../crypto/web-crypto.js";
import type { Database } from "../db/database.js";
import type { Result } from "../mcp/types.js";
import { loadCheckpointTree, verifyInclusionProof } from "./checkpoint.js";
import {
	fieldCommitment,
	fieldSalt,
	leafPreimage,
	loadLeaf,
	receiptFieldsFor,
	resolveReceiptKey,
} from "./checkpoint-leaves.js";
import { merkleLeafHash } from "./checkpoint-merkle.js";
import { bytesToHex, hexToBytes, isHashHex } from "./checkpoint-sign.js";
import type {
	Checkpoint,
	CheckpointPublicKey,
	Receipt,
	VerifyOutcome,
} from "./checkpoint-types.js";

export interface CreateReceiptOptions {
	/** Names of the decision fields to reveal. Every other field stays a salted commitment. */
	reveal: readonly string[];
	hmacKey?: string;
}

function fail<T>(code: string, message: string): Result<T> {
	return { success: false, error: { code, message } };
}

/** Build a receipt for one row against a checkpoint that already covers it. */
export async function createReceipt(
	db: Database,
	rowId: string,
	checkpoint: Checkpoint,
	opts: CreateReceiptOptions,
): Promise<Result<Receipt>> {
	try {
		const covered = await loadCheckpointTree(db, checkpoint, opts.hmacKey);
		if (!covered.success) return covered;
		const { ids, hashes, tree } = covered.data;
		const index = ids.indexOf(rowId);
		if (index < 0) return fail("ROW_NOT_FOUND", "The row is not covered by this checkpoint");
		const leaf = await loadLeaf(db, rowId, opts.hmacKey);
		const covering = hashes[index];
		if (!leaf || !covering || !constantTimeEqual(leaf.leafHash, covering)) {
			return fail("LOG_MISMATCH", "The row changed while the receipt was being built");
		}

		const hashVersion = leaf.row.hashVersion ?? 1;
		const allowed = receiptFieldsFor(hashVersion);
		for (const name of opts.reveal) {
			if (!allowed.includes(name)) {
				return fail("INVALID_FIELD", `Field "${name}" cannot be revealed for this row`);
			}
		}
		const revealed: Receipt["decision"]["revealed"] = {};
		const commitments: Record<string, string> = {};
		const key = await resolveReceiptKey(db, opts.hmacKey);
		for (const name of allowed) {
			if (opts.reveal.includes(name)) {
				revealed[name] = {
					value: leaf.fieldValues[name],
					salt: await fieldSalt(key, leaf.rowHash, name),
				};
			} else {
				commitments[name] = leaf.commitments[name] as string;
			}
		}
		const path = await tree.inclusionPath(index);
		return {
			success: true,
			data: {
				version: 1,
				decision: { rowId, rowHash: leaf.rowHash, hashVersion, revealed, commitments },
				proof: {
					version: 1,
					rowId,
					leafIndex: index,
					treeSize: checkpoint.size,
					leafHash: bytesToHex(leaf.leafHash),
					path: path.map(bytesToHex),
				},
				checkpoint,
			},
		};
	} catch (error) {
		return fail("RECEIPT_FAILED", error instanceof Error ? error.message : "Unknown");
	}
}

function receiptShapeOk(r: Receipt): boolean {
	const d = r?.decision;
	return (
		r?.version === 1 &&
		typeof d === "object" &&
		d !== null &&
		typeof d.rowId === "string" &&
		typeof d.rowHash === "string" &&
		Number.isSafeInteger(d.hashVersion) &&
		typeof d.revealed === "object" &&
		d.revealed !== null &&
		typeof d.commitments === "object" &&
		d.commitments !== null &&
		typeof r.proof === "object" &&
		r.proof !== null &&
		d.rowId === r.proof.rowId
	);
}

/**
 * Verify a receipt offline: the checkpoint signature, that the revealed values
 * match their commitments, and that the resulting leaf is in the checkpoint tree.
 */
export async function verifyReceipt(
	receipt: Receipt,
	publicKey: CheckpointPublicKey | readonly CheckpointPublicKey[],
): Promise<VerifyOutcome> {
	if (!receiptShapeOk(receipt)) return { valid: false, reason: "malformed" };
	const { decision, proof, checkpoint } = receipt;
	const allowed = receiptFieldsFor(decision.hashVersion);
	const names = [...Object.keys(decision.revealed), ...Object.keys(decision.commitments)];
	if (
		names.length !== allowed.length ||
		new Set(names).size !== names.length ||
		!names.every((n) => allowed.includes(n))
	) {
		return { valid: false, reason: "malformed" };
	}

	const commitments: Record<string, string> = {};
	for (const [name, hidden] of Object.entries(decision.commitments)) {
		if (!isHashHex(hidden)) return { valid: false, reason: "malformed" };
		commitments[name] = hidden;
	}
	for (const [name, field] of Object.entries(decision.revealed)) {
		if (typeof field !== "object" || field === null || !isHashHex(field.salt)) {
			return { valid: false, reason: "malformed" };
		}
		try {
			commitments[name] = await fieldCommitment(name, field.salt, field.value);
		} catch {
			return { valid: false, reason: "bad_commitment" };
		}
	}

	const leafHash = bytesToHex(
		await merkleLeafHash(
			leafPreimage(decision.rowId, decision.rowHash, decision.hashVersion, commitments),
		),
	);
	if (
		!isHashHex(proof.leafHash) ||
		!constantTimeEqual(hexToBytes(leafHash), hexToBytes(proof.leafHash))
	) {
		return { valid: false, reason: "leaf_mismatch" };
	}
	return verifyInclusionProof(proof, checkpoint, publicKey);
}
