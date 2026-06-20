import { exportJWK, generateKeyPair } from "jose";
import type { DidDocument, DidKeyPair, VerificationMethod } from "./types.js";

// Bitcoin base58 alphabet (same as multibase base58btc)
const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/**
 * Encode a Uint8Array to base58btc string.
 * Implements Bitcoin's base58 encoding algorithm.
 */
function base58btcEncode(bytes: Uint8Array): string {
	// Count leading zero bytes — each maps to '1' in base58
	let leadingZeros = 0;
	for (const byte of bytes) {
		if (byte !== 0) break;
		leadingZeros++;
	}

	// Convert big-endian byte array to a big integer via positional arithmetic
	const digits: number[] = [0];
	for (const byte of bytes) {
		let carry = byte;
		for (let i = 0; i < digits.length; i++) {
			carry += (digits[i] ?? 0) * 256;
			digits[i] = carry % 58;
			carry = Math.floor(carry / 58);
		}
		while (carry > 0) {
			digits.push(carry % 58);
			carry = Math.floor(carry / 58);
		}
	}

	// Convert digit array (little-endian) to string (big-endian)
	const result = digits
		.reverse()
		.map((d) => BASE58_ALPHABET[d] ?? "1")
		.join("");

	return "1".repeat(leadingZeros) + result;
}

/**
 * Decode a base64url string to raw bytes (Uint8Array).
 * Works without Node.js Buffer — uses atob after padding normalisation.
 */
function base64urlToBytes(b64url: string): Uint8Array {
	// Restore standard base64 padding and characters
	const padded = b64url.replace(/-/g, "+").replace(/_/g, "/");
	const padLen = (4 - (padded.length % 4)) % 4;
	const b64 = padded + "=".repeat(padLen);

	// atob is available in both Node.js 16+ (global) and browsers
	const binary = atob(b64);
	const bytes = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) {
		bytes[i] = binary.charCodeAt(i);
	}
	return bytes;
}

/**
 * Derive the multibase-encoded did:key identifier from an Ed25519 public key.
 *
 * Encoding: base58btc(multicodec_ed25519_prefix || raw_public_key_bytes)
 * Ed25519 multicodec prefix: 0xed 0x01
 * The resulting multibase string is prefixed with 'z' (base58btc indicator).
 */
function publicKeyJwkToDidKey(publicKeyJwk: JsonWebKey): string {
	if (!publicKeyJwk.x) {
		throw new Error("Ed25519 JWK must have an 'x' parameter");
	}
	const rawKey = base64urlToBytes(publicKeyJwk.x);

	// Ed25519 multicodec prefix
	const prefix = new Uint8Array([0xed, 0x01]);
	const multicodecKey = new Uint8Array(prefix.length + rawKey.length);
	multicodecKey.set(prefix);
	multicodecKey.set(rawKey, prefix.length);

	return `did:key:z${base58btcEncode(multicodecKey)}`;
}

/**
 * Build a W3C DID Document for a did:key identifier.
 */
export function buildDidDocument(did: string, publicKeyJwk: JsonWebKey): DidDocument {
	const keyId = `${did}#${did.slice("did:key:".length)}`;

	const verificationMethod: VerificationMethod = {
		id: keyId,
		type: "JsonWebKey2020",
		controller: did,
		publicKeyJwk,
	};

	return {
		"@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/jws-2020/v1"],
		id: did,
		controller: did,
		verificationMethod: [verificationMethod],
		authentication: [keyId],
		assertionMethod: [keyId],
		capabilityInvocation: [keyId],
		capabilityDelegation: [keyId],
	};
}

/**
 * Generate a new did:key identity using Ed25519.
 *
 * Returns the DID, key pair (JWK format), and auto-generated DID document.
 * The private key is returned to the caller and must be stored securely —
 * it is never persisted by TheAuth.
 */
export async function generateDidKey(): Promise<DidKeyPair> {
	const { publicKey, privateKey } = await generateKeyPair("EdDSA", {
		crv: "Ed25519",
		extractable: true,
	});

	const publicKeyJwk = await exportJWK(publicKey);
	const privateKeyJwk = await exportJWK(privateKey);

	// Ensure the JWK has the curve set (jose may omit it)
	publicKeyJwk.crv = "Ed25519";
	publicKeyJwk.kty = "OKP";
	privateKeyJwk.crv = "Ed25519";
	privateKeyJwk.kty = "OKP";

	const did = publicKeyJwkToDidKey(publicKeyJwk);
	const didDocument = buildDidDocument(did, publicKeyJwk);

	return {
		did,
		publicKeyJwk,
		privateKeyJwk,
		didDocument,
	};
}

/**
 * Resolve a did:key to its DID document.
 *
 * did:key is self-describing — the public key is embedded in the identifier
 * via multibase(multicodec(raw_key)), so resolution is purely local.
 * Returns null if the DID is malformed.
 */
export function resolveDidKey(did: string): DidDocument | null {
	if (!did.startsWith("did:key:z")) return null;

	// We reconstruct the DID document by building it from the DID itself.
	// The public key bytes could be decoded, but for the document we only
	// need the DID string and a placeholder JWK — the key ID references
	// the full DID which encodes the key material.
	//
	// For a proper verifier, callers should use verifyPayload() which
	// accepts the public key JWK directly.
	const keyId = `${did}#${did.slice("did:key:".length)}`;

	const verificationMethod: VerificationMethod = {
		id: keyId,
		type: "JsonWebKey2020",
		controller: did,
		// Public key JWK is not reconstructed here — callers who need to verify
		// signatures supply the JWK separately via verifyPayload().
		publicKeyJwk: { kty: "OKP", crv: "Ed25519" },
	};

	return {
		"@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/jws-2020/v1"],
		id: did,
		controller: did,
		verificationMethod: [verificationMethod],
		authentication: [keyId],
		assertionMethod: [keyId],
		capabilityInvocation: [keyId],
		capabilityDelegation: [keyId],
	};
}
