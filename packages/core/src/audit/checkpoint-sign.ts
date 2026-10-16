/**
 * Ed25519 signing and verification for checkpoints, through Web Crypto (the same
 * runtime support as the rest of core: Node 20+, Workers, Deno, Bun).
 */

import { fromBase64Url, fromHex, toBase64Url, toHex } from "../crypto/web-crypto.js";
import { canonicalJson } from "./chain.js";
import type {
	Checkpoint,
	CheckpointPublicKey,
	CheckpointSigner,
	VerifyOutcome,
} from "./checkpoint-types.js";

const ENCODER = new TextEncoder();
const SIGN_DOMAIN = "theauth.audit.checkpoint.v1\n";
const HASH_HEX = /^[0-9a-f]{64}$/;
const ED25519_SIGNATURE_BYTES = 64;

function buffer(bytes: Uint8Array): ArrayBuffer {
	return (bytes.buffer as ArrayBuffer).slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
}

export function isHashHex(value: unknown): value is string {
	return typeof value === "string" && HASH_HEX.test(value);
}

export function hexToBytes(hex: string): Uint8Array {
	return fromHex(hex);
}

export function bytesToHex(bytes: Uint8Array): string {
	return toHex(bytes);
}

/** Generate an Ed25519 key pair for signing checkpoints. Store the private JWK like any signing secret. */
export async function generateCheckpointKeyPair(keyId: string): Promise<{
	signer: CheckpointSigner;
	publicKey: CheckpointPublicKey;
	privateKeyJwk: JsonWebKey;
}> {
	const pair = await globalThis.crypto.subtle.generateKey({ name: "Ed25519" }, true, [
		"sign",
		"verify",
	]);
	if (!("privateKey" in pair)) throw new Error("Ed25519 key generation returned no key pair");
	const privateKeyJwk = await globalThis.crypto.subtle.exportKey("jwk", pair.privateKey);
	const publicJwk = await globalThis.crypto.subtle.exportKey("jwk", pair.publicKey);
	return {
		signer: await createEd25519Signer(privateKeyJwk, keyId),
		publicKey: { keyId, publicKey: { kty: "OKP", crv: "Ed25519", x: publicJwk.x } },
		privateKeyJwk,
	};
}

/** Build a signer from an Ed25519 private JWK held in process. */
export async function createEd25519Signer(
	privateKeyJwk: JsonWebKey,
	keyId: string,
): Promise<CheckpointSigner> {
	const key = await globalThis.crypto.subtle.importKey(
		"jwk",
		privateKeyJwk,
		{ name: "Ed25519" },
		false,
		["sign"],
	);
	return {
		keyId,
		async sign(message: Uint8Array): Promise<Uint8Array> {
			const sig = await globalThis.crypto.subtle.sign({ name: "Ed25519" }, key, buffer(message));
			return new Uint8Array(sig);
		},
	};
}

type UnsignedCheckpoint = Omit<Checkpoint, "signature">;

function signedBytes(cp: UnsignedCheckpoint): Uint8Array {
	return ENCODER.encode(
		SIGN_DOMAIN +
			canonicalJson({
				version: cp.version,
				alg: cp.alg,
				keyId: cp.keyId,
				size: cp.size,
				rootHash: cp.rootHash,
				timestamp: cp.timestamp,
				since: cp.since,
				until: cp.until,
			}),
	);
}

export async function signCheckpoint(
	signer: CheckpointSigner,
	body: UnsignedCheckpoint,
): Promise<Checkpoint> {
	const signature = await signer.sign(signedBytes(body));
	if (signature.length !== ED25519_SIGNATURE_BYTES) {
		throw new Error("checkpoint signer did not return a 64 byte Ed25519 signature");
	}
	return { ...body, signature: toBase64Url(signature) };
}

function isNullableTime(v: unknown): v is number | null {
	return v === null || (typeof v === "number" && Number.isSafeInteger(v) && v >= 0);
}

/** Shape check only. Says nothing about the signature. */
export function isWellFormedCheckpoint(cp: unknown): cp is Checkpoint {
	if (typeof cp !== "object" || cp === null) return false;
	const c = cp as Record<string, unknown>;
	return (
		c.version === 1 &&
		typeof c.alg === "string" &&
		typeof c.keyId === "string" &&
		typeof c.size === "number" &&
		Number.isSafeInteger(c.size) &&
		c.size >= 0 &&
		isHashHex(c.rootHash) &&
		typeof c.timestamp === "number" &&
		Number.isSafeInteger(c.timestamp) &&
		isNullableTime(c.since) &&
		isNullableTime(c.until) &&
		typeof c.signature === "string"
	);
}

/**
 * Verify a checkpoint signature. Rejects any algorithm other than Ed25519 and
 * any keyId that none of the supplied keys carries, so a checkpoint cannot pick
 * the key or the algorithm it is checked with. Pass several keys to cover key
 * rotation.
 */
export async function verifyCheckpoint(
	checkpoint: Checkpoint,
	publicKey: CheckpointPublicKey | readonly CheckpointPublicKey[],
): Promise<VerifyOutcome> {
	if (!isWellFormedCheckpoint(checkpoint)) return { valid: false, reason: "malformed" };
	if ((checkpoint.alg as string) !== "Ed25519") return { valid: false, reason: "unsupported_alg" };
	const keys = Array.isArray(publicKey) ? publicKey : [publicKey as CheckpointPublicKey];
	const match = keys.find((k) => k.keyId === checkpoint.keyId);
	if (!match) return { valid: false, reason: "unknown_key" };
	try {
		if (match.publicKey.kty !== "OKP" || match.publicKey.crv !== "Ed25519") {
			return { valid: false, reason: "unsupported_alg" };
		}
		const key = await globalThis.crypto.subtle.importKey(
			"jwk",
			{ kty: "OKP", crv: "Ed25519", x: match.publicKey.x },
			{ name: "Ed25519" },
			false,
			["verify"],
		);
		const signature = fromBase64Url(checkpoint.signature);
		if (signature.length !== ED25519_SIGNATURE_BYTES)
			return { valid: false, reason: "bad_signature" };
		const ok = await globalThis.crypto.subtle.verify(
			{ name: "Ed25519" },
			key,
			buffer(signature),
			buffer(signedBytes(checkpoint)),
		);
		return ok ? { valid: true } : { valid: false, reason: "bad_signature" };
	} catch {
		return { valid: false, reason: "bad_signature" };
	}
}
