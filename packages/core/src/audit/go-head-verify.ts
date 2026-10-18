/**
 * Verifier for the signed head checkpoint written by theauth-go (`audit/checkpoint` HeadCheckpoint).
 *
 * A hash chain walked row by row cannot show that rows were cut off its end, because every remaining
 * row still links to the one before it. The Go library signs the last position of every chain
 * (`chainKey`, `seq`, `hash`) and this file checks that signature and then compares the signed
 * positions with exported rows, the way a Certificate Transparency monitor compares a signed tree
 * head (RFC 6962 section 3.5) with the log it watches.
 *
 * Wire format (go/docs/storage-capabilities.md, "Head checkpoints"): JSON
 * `{version: 1, alg: "Ed25519", keyId, timestamp (ms), heads: [{chainKey, seq, hash}], signature}`
 * with heads sorted by chainKey (UTF-8 byte order). The signature is Ed25519 (RFC 8032), base64url
 * without padding, over the bytes `theauth.audit.head.v1\n` followed by the canonical JSON (sorted
 * keys, no whitespace) of `{version, alg, keyId, timestamp, heads}`. Test vectors written by the Go
 * code are in tests/fixtures/go-head-checkpoint-vectors.json.
 */

import { fromBase64Url, toBase64Url } from "../crypto/web-crypto.js";
import { canonicalJson } from "./chain.js";
import type { CheckpointPublicKey } from "./checkpoint-types.js";

const HEAD_SIGN_DOMAIN = "theauth.audit.head.v1\n";
const HASH_HEX = /^[0-9a-f]{64}$/;
const SIGNATURE_BYTES = 64;
const PUBLIC_KEY_BYTES = 32;
const ENCODER = new TextEncoder();

/** The last position of one chain at signing time. */
export interface GoChainHead {
	/** Organization id, or the empty string for the global chain. */
	chainKey: string;
	/** Highest chain sequence number, counting from 1. */
	seq: number;
	/** Lowercase hex chain hash of the row at `seq`. */
	hash: string;
}

/** A signed set of chain heads, as `checkpoint.CreateHeadCheckpoint` writes it. */
export interface GoHeadCheckpoint {
	version: 1;
	alg: "Ed25519";
	keyId: string;
	/** Signing time, milliseconds since the epoch. */
	timestamp: number;
	heads: GoChainHead[];
	/** Base64url Ed25519 signature over the other fields. */
	signature: string;
}

/** The parts of an exported Go audit row that a head check reads. */
export interface GoHeadRow {
	organizationId?: string | null;
	chainSeq?: number | null;
	hash?: string | null;
}

/** Stable codes, identical to the Go `Reason` values. */
export type GoHeadFailureReason =
	| "malformed"
	| "unsupported_alg"
	| "unknown_key"
	| "bad_signature"
	| "chain_truncated"
	| "head_mismatch";

export type GoHeadResult =
	| { valid: true }
	/** `chainKey` is the first chain that failed, set for `chain_truncated` and `head_mismatch`. */
	| { valid: false; reason: GoHeadFailureReason; chainKey?: string };

function fail(reason: GoHeadFailureReason, chainKey?: string): GoHeadResult {
	return chainKey === undefined ? { valid: false, reason } : { valid: false, reason, chainKey };
}

function buffer(bytes: Uint8Array): ArrayBuffer {
	return (bytes.buffer as ArrayBuffer).slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
}

/** Go compares chain keys as byte strings (UTF-8), JavaScript `<` compares UTF-16 code units. */
function compareUtf8(a: string, b: string): number {
	const x = ENCODER.encode(a);
	const y = ENCODER.encode(b);
	const n = Math.min(x.length, y.length);
	for (let i = 0; i < n; i++) {
		const d = (x[i] as number) - (y[i] as number);
		if (d !== 0) return d;
	}
	return x.length - y.length;
}

function isSafeSeq(v: unknown): v is number {
	return typeof v === "number" && Number.isSafeInteger(v) && v >= 1;
}

/** Shape check only, the same rules as Go `headWellFormed`. Says nothing about the signature. */
export function isWellFormedGoHead(value: unknown): value is GoHeadCheckpoint {
	if (typeof value !== "object" || value === null) return false;
	const h = value as Record<string, unknown>;
	if (h.version !== 1 || typeof h.alg !== "string" || typeof h.keyId !== "string") return false;
	if (typeof h.signature !== "string" || !Array.isArray(h.heads)) return false;
	if (typeof h.timestamp !== "number" || !Number.isSafeInteger(h.timestamp) || h.timestamp < 0) {
		return false;
	}
	let prev: string | null = null;
	for (const c of h.heads as unknown[]) {
		if (typeof c !== "object" || c === null) return false;
		const e = c as Record<string, unknown>;
		if (typeof e.chainKey !== "string" || !isSafeSeq(e.seq)) return false;
		if (typeof e.hash !== "string" || !HASH_HEX.test(e.hash)) return false;
		if (prev !== null && compareUtf8(prev, e.chainKey) >= 0) return false;
		prev = e.chainKey;
	}
	return true;
}

function signedBytes(h: GoHeadCheckpoint): Uint8Array {
	return ENCODER.encode(
		HEAD_SIGN_DOMAIN +
			canonicalJson({
				version: h.version,
				alg: h.alg,
				keyId: h.keyId,
				timestamp: h.timestamp,
				heads: h.heads.map((c) => ({ chainKey: c.chainKey, seq: c.seq, hash: c.hash })),
			}),
	);
}

/** Strict base64url decode: no padding, no stray trailing bits, like Go `RawURLEncoding.Strict()`. */
function decodeStrict(text: string): Uint8Array | null {
	try {
		const bytes = fromBase64Url(text);
		return toBase64Url(bytes) === text ? bytes : null;
	} catch {
		return null;
	}
}

/**
 * Check the signature and shape of a head checkpoint offline. Rejects any algorithm other than
 * Ed25519 and any `keyId` that none of the supplied keys carries, so a head cannot pick its own key.
 * Pass several keys to cover key rotation. Never throws on hostile input.
 */
export async function verifyGoHeadSignature(
	head: unknown,
	publicKey: CheckpointPublicKey | readonly CheckpointPublicKey[],
): Promise<GoHeadResult> {
	try {
		if (!isWellFormedGoHead(head)) return fail("malformed");
		if ((head.alg as string) !== "Ed25519") return fail("unsupported_alg");
		const list: unknown[] = Array.isArray(publicKey) ? publicKey : [publicKey];
		const match = list.find(
			(k): k is CheckpointPublicKey =>
				typeof k === "object" && k !== null && (k as CheckpointPublicKey).keyId === head.keyId,
		);
		if (!match) return fail("unknown_key");
		const jwk = match.publicKey;
		if (jwk?.kty !== "OKP" || jwk.crv !== "Ed25519") return fail("unsupported_alg");
		const pub = typeof jwk.x === "string" ? decodeStrict(jwk.x) : null;
		const sig = decodeStrict(head.signature);
		if (pub?.length !== PUBLIC_KEY_BYTES || sig?.length !== SIGNATURE_BYTES) {
			return fail("bad_signature");
		}
		const key = await globalThis.crypto.subtle.importKey(
			"raw",
			buffer(pub),
			{ name: "Ed25519" },
			false,
			["verify"],
		);
		const ok = await globalThis.crypto.subtle.verify(
			{ name: "Ed25519" },
			key,
			buffer(sig),
			buffer(signedBytes(head)),
		);
		return ok ? { valid: true } : fail("bad_signature");
	} catch {
		return fail("bad_signature");
	}
}

/**
 * Verify a head checkpoint written by theauth-go and, when `rows` is given, compare it with the
 * exported rows: every signed chain must still reach its signed `seq` with the signed hash. Chains
 * and rows added after signing are fine. Without `rows` this is a signature check only.
 *
 * Results match Go `CheckHeadCheckpoint`: `chain_truncated` when a chain is missing or shorter than
 * signed, `head_mismatch` when the row at the signed seq has another hash (or is not in the rows).
 * One difference, on the safe side: two rows that claim the signed seq with different hashes are a
 * `head_mismatch` here, where Go keeps the last one it reads.
 *
 * This looks only at the signed positions. Run `verifyGoAuditChain` on the same rows as well. The
 * rows must cover every chain from the signed seq up, so do not pass a window that stops early.
 */
export async function verifyGoHeadCheckpoint(
	head: unknown,
	publicKey: CheckpointPublicKey | readonly CheckpointPublicKey[],
	rows?: readonly GoHeadRow[],
): Promise<GoHeadResult> {
	const signed = await verifyGoHeadSignature(head, publicKey);
	if (!signed.valid || rows === undefined) return signed;
	const checkpoint = head as GoHeadCheckpoint;
	const want = new Map<string, number>();
	for (const c of checkpoint.heads) want.set(c.chainKey, c.seq);
	const top = new Map<string, number>();
	const atSeq = new Map<string, Set<string>>();
	for (const row of rows) {
		if (typeof row !== "object" || row === null) continue;
		const hash = row.hash;
		const seq = row.chainSeq;
		if (typeof hash !== "string" || hash === "" || !isSafeSeq(seq)) continue;
		const key = typeof row.organizationId === "string" ? row.organizationId : "";
		if (seq > (top.get(key) ?? 0)) top.set(key, seq);
		if (want.get(key) === seq) {
			const set = atSeq.get(key) ?? new Set<string>();
			set.add(hash.toLowerCase());
			atSeq.set(key, set);
		}
	}
	for (const c of checkpoint.heads) {
		if ((top.get(c.chainKey) ?? 0) < c.seq) return fail("chain_truncated", c.chainKey);
		const seen = atSeq.get(c.chainKey);
		if (seen?.size !== 1 || !seen.has(c.hash)) return fail("head_mismatch", c.chainKey);
	}
	return { valid: true };
}
