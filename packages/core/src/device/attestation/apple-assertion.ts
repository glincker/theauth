import { z } from "zod";
import { constantTimeEqual, sha256Raw } from "../../crypto/web-crypto.js";
import { decodeCborExact } from "./cbor.js";
import { ecdsaDerToRaw } from "./x509.js";

/**
 * Apple App Attest assertions (Apple's "Validating apps that connect to your server", assertion steps).
 *
 * An assertion proves a request came from the same app instance whose key was attested at enrollment. The app calls `generateAssertion(keyId, clientDataHash)`. The result is a CBOR map `{ signature, authenticatorData }`. The server:
 * 1. hashes the client data (`SHA-256(clientData)`),
 * 2. computes `nonce = SHA-256(authenticatorData || clientDataHash)`,
 * 3. verifies the ECDSA signature (SHA-256) over `nonce` with the attested public key,
 * 4. checks `rpIdHash` equals `SHA-256(appId)`,
 * 5. checks the counter is strictly greater than the last one stored for the key.
 * Replay protection is the counter plus a challenge inside the client data: the caller stores the counter atomically (see `device.verifyAppAssertion`) and binds a server nonce into the client data.
 * Fixtures: veehaitch/devicecheck-appattest (Apache-2.0, iOS 14.4 device) and a block/buzz iOS 27 assertion (Apache-2.0) whose authenticatorData carries extension bytes.
 */
export interface AppleAssertionInput {
	/** The assertion object, base64 or base64url of the CBOR map. */
	assertion: string | Uint8Array;
	/** The exact bytes the app hashed to make `clientDataHash`. */
	clientData: string | Uint8Array;
	/** `<TeamID>.<BundleID>` the assertion must be for. */
	appId: string;
	/** The attested public key as an X9.62 uncompressed point (65 bytes), base64 or raw. This is the `attestedPublicKey` claim of `createAppleAppAttestVerifier`. */
	publicKey: string | Uint8Array;
	/** The highest counter accepted so far for this key. 0 right after attestation. */
	previousCounter: number;
}

export type AppleAssertionResult =
	| { ok: true; counter: number; flags: number }
	| { ok: false; reason: string };

const AssertionSchema = z.object({
	signature: z.instanceof(Uint8Array),
	authenticatorData: z.instanceof(Uint8Array),
});

function decodeBase64(text: string): Uint8Array {
	const std = text.replace(/-/g, "+").replace(/_/g, "/");
	const padded = std + "=".repeat((4 - (std.length % 4)) % 4);
	const bin = atob(padded);
	const out = new Uint8Array(bin.length);
	for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
	return out;
}

function toBytes(v: string | Uint8Array): Uint8Array {
	return typeof v === "string" ? decodeBase64(v) : v;
}

function copy(b: Uint8Array): Uint8Array<ArrayBuffer> {
	const out = new Uint8Array(new ArrayBuffer(b.length));
	out.set(b);
	return out;
}

/** Counters are unsigned 32 bit in authenticatorData. Anything else cannot be a counter. */
function validCounter(n: number): boolean {
	return Number.isInteger(n) && n >= 0 && n <= 0xffff_ffff;
}

export async function verifyAppleAssertion(
	input: AppleAssertionInput,
): Promise<AppleAssertionResult> {
	const fail = (reason: string): AppleAssertionResult => ({ ok: false, reason });
	if (!validCounter(input.previousCounter)) return fail("Stored counter is not valid");
	let raw: Uint8Array;
	let point: Uint8Array;
	try {
		raw = toBytes(input.assertion);
		point = toBytes(input.publicKey);
	} catch {
		return fail("Assertion or key is not base64");
	}
	if (point.length !== 65 || point[0] !== 4)
		return fail("Public key is not an uncompressed P-256 point");
	let parsed: z.infer<typeof AssertionSchema>;
	try {
		const map = decodeCborExact(raw);
		if (!(map instanceof Map)) return fail("Assertion is not a CBOR map");
		const result = AssertionSchema.safeParse({
			signature: map.get("signature"),
			authenticatorData: map.get("authenticatorData"),
		});
		if (!result.success) return fail("Assertion needs signature and authenticatorData");
		parsed = result.data;
	} catch {
		return fail("Assertion is not valid CBOR");
	}
	const auth = parsed.authenticatorData;
	// rpIdHash (32) + flags (1) + counter (4). Apple may append extension bytes after the counter, the signature covers them.
	if (auth.length < 37) return fail("authenticatorData is too short");
	const rpIdHash = auth.subarray(0, 32);
	if (!constantTimeEqual(rpIdHash, await sha256Raw(input.appId))) {
		return fail("Assertion is not for this App ID");
	}
	const view = new DataView(auth.buffer, auth.byteOffset, auth.byteLength);
	const counter = view.getUint32(33, false);
	const clientDataHash = await sha256Raw(
		typeof input.clientData === "string"
			? new TextEncoder().encode(input.clientData)
			: input.clientData,
	);
	const joined = new Uint8Array(auth.length + clientDataHash.length);
	joined.set(auth, 0);
	joined.set(clientDataHash, auth.length);
	const nonce = await sha256Raw(joined);
	let valid = false;
	try {
		const key = await globalThis.crypto.subtle.importKey(
			"raw",
			copy(point),
			{ name: "ECDSA", namedCurve: "P-256" },
			false,
			["verify"],
		);
		const sig = ecdsaDerToRaw(parsed.signature, 32);
		valid = await globalThis.crypto.subtle.verify(
			{ name: "ECDSA", hash: "SHA-256" },
			key,
			copy(sig),
			copy(nonce),
		);
	} catch {
		valid = false;
	}
	if (!valid) return fail("Assertion signature is not valid");
	// Checked after the signature so an unsigned counter never decides anything.
	if (counter <= input.previousCounter) return fail("Assertion counter did not increase");
	return { ok: true, counter, flags: auth[32] as number };
}
