/** Shared types for signed audit checkpoints, inclusion proofs, consistency proofs and receipts. */

/** Signs checkpoint bytes. Wrap a KMS or HSM call here; the private key never has to be in process. */
export interface CheckpointSigner {
	/** Identifies the key. Verifiers pick the public key by this id and reject a mismatch. */
	keyId: string;
	sign(message: Uint8Array): Promise<Uint8Array>;
}

/** An Ed25519 public key (JWK, kty OKP, crv Ed25519) and the id it is published under. */
export interface CheckpointPublicKey {
	keyId: string;
	publicKey: JsonWebKey;
}

/** Signed tree head: the state of the log at a point in time. */
export interface Checkpoint {
	version: 1;
	/** Always "Ed25519". Anything else is rejected. */
	alg: "Ed25519";
	keyId: string;
	/** Number of leaves in the tree. */
	size: number;
	/** Hex SHA-256 Merkle root (RFC 6962). */
	rootHash: string;
	/** Signing time, milliseconds since the epoch. */
	timestamp: number;
	/** Lower bound (ms) of the row timestamps this tree covers, or null for the whole log. */
	since: number | null;
	/** Upper bound (ms) of the row timestamps this tree covers, or null for no bound. */
	until: number | null;
	/** Base64url Ed25519 signature over the other fields. */
	signature: string;
}

export interface InclusionProof {
	version: 1;
	rowId: string;
	/** Zero-based position of the row's leaf. */
	leafIndex: number;
	/** Size of the tree the path was built for. Must equal the checkpoint size. */
	treeSize: number;
	/** Hex leaf hash. */
	leafHash: string;
	/** Hex sibling hashes from the leaf up to the root. */
	path: string[];
}

export interface ConsistencyProof {
	version: 1;
	oldSize: number;
	newSize: number;
	/** Hex hashes (RFC 6962 consistency proof). */
	path: string[];
}

/** Why a verification failed. Stable codes, safe to branch on. */
export type VerifyFailureReason =
	| "malformed"
	| "unsupported_alg"
	| "unknown_key"
	| "bad_signature"
	| "size_mismatch"
	| "scope_mismatch"
	| "bad_proof"
	| "leaf_mismatch"
	| "bad_commitment";

export type VerifyOutcome = { valid: true } | { valid: false; reason: VerifyFailureReason };

export interface CheckpointStore {
	/** Save a checkpoint. Saving the same checkpoint twice is a no-op. */
	put(checkpoint: Checkpoint): Promise<void>;
	/** The checkpoint with the largest size (latest timestamp on a tie). */
	latest(): Promise<Checkpoint | undefined>;
	/** All checkpoints of exactly this size, oldest first. */
	getBySize(size: number): Promise<Checkpoint[]>;
	/** Every stored checkpoint, ordered by size then timestamp. */
	list(): Promise<Checkpoint[]>;
}

/** Fields a receipt can reveal for one row. Version 2 rows commit to idPseudonyms, version 1 rows to the raw ids. */
export const RECEIPT_FIELDS_V2 = [
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
] as const;

export const RECEIPT_FIELDS_V1 = [
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
	"agentId",
	"userId",
] as const;

export interface ReceiptRevealedField {
	value: unknown;
	/** Hex per-field salt. Only revealed fields carry one. */
	salt: string;
}

export interface ReceiptDecision {
	rowId: string;
	/** The row's chain hash. It covers every field, including the hidden ones. */
	rowHash: string;
	hashVersion: number;
	revealed: Record<string, ReceiptRevealedField>;
	/** Hex commitments for the fields that are not revealed. */
	commitments: Record<string, string>;
}

export interface Receipt {
	version: 1;
	decision: ReceiptDecision;
	proof: InclusionProof;
	checkpoint: Checkpoint;
}
