import { z } from "zod";
import { constantTimeEqual, fromBase64Url, fromHex, sha256Raw } from "../../crypto/web-crypto.js";
import type { DeviceAttestationInput, DeviceAttestationResult } from "../types.js";
import { APPLE_APP_ATTEST_ROOTS } from "./apple-roots.js";
import { decodeCborExact, decodeCborPrefix } from "./cbor.js";
import { bitStringBytes, children, isUniversal, parseOne, TAG } from "./der.js";
import { keyThumbprint } from "./key-thumbprint.js";
import type { X509Cert } from "./x509.js";
import { certBytesFromText, parseCertificate, spkiInfo, verifyChain } from "./x509.js";

/** Extension of the credential certificate that carries the nonce (Apple's validation guide, step 4). */
const NONCE_OID = "1.2.840.113635.100.8.2";
const AAGUID_PRODUCTION = new TextEncoder().encode("appattest\0\0\0\0\0\0\0");
const AAGUID_DEVELOPMENT = new TextEncoder().encode("appattestdevelop");

export interface AppleAppAttestOptions {
	/**
	 * Accepted App IDs, each `<TeamID>.<BundleID>`. Required: the attestation proves a key lives in some app on a genuine Apple device, and the App ID hash is how you know it is yours. An empty list refuses everything.
	 */
	appIds: readonly string[];
	/** Trust anchors as PEM or base64 DER. Default: the Apple App Attestation Root CA bundled with this library. */
	roots?: readonly string[];
	/** `production` (default) accepts the production AAGUID only, `development` the sandbox one only, `any` both. Sandbox keys prove less, so keep production in production. */
	environment?: "production" | "development" | "any";
	/**
	 * How the attestation is tied to the credential the device enrolls (credential kind `jwk`, RFC 7638 thumbprint).
	 * `client-data` (default): the app hashes `<nonce>:<thumbprint>` as its client data, so Apple's certificate vouches for that exact pairing. App Attest keys cannot be exported or used as a device credential, so this is the usual way to bind a separate enrolled key.
	 * `attested-key`: the enrolled key must be the App Attest key itself, which only works if you extract its public key from the attestation yourself.
	 * `none`: nonce only. A genuine app on a genuine device vouched for the nonce, nothing ties it to the enrolled credential.
	 */
	bind?: "client-data" | "attested-key" | "none";
	/**
	 * How the app derived `clientDataHash` from the client data (the nonce, or `<nonce>:<thumbprint>` with `bind: "client-data"`). `sha256` (default) is SHA-256 of the nonce bytes. `raw` means the app passed the nonce bytes themselves, which Apple's own sample does.
	 */
	clientDataHash?: "sha256" | "raw";
	/** How the nonce string maps to bytes. Default `utf8`. */
	challengeEncoding?: "utf8" | "base64url" | "hex";
	/** When set, the `apple_validation_category_01` extension must be present and one of these values (1 is what Apple's guide shows for an OS distributed app). */
	allowedValidationCategories?: readonly number[];
	/** Clock for validity checks. Tests inject one. */
	now?: () => Date;
}

const EvidenceSchema = z.object({
	attestation: z.string().min(1).max(65536),
	keyId: z.string().min(1).max(128),
});

/** Evidence is JSON: `{ "attestation": "<base64 attestation object>", "keyId": "<base64 key identifier>" }`. */
export function parseAppleAppAttestEvidence(evidence: string): {
	attestation: Uint8Array;
	keyId: Uint8Array;
} {
	let json: unknown;
	try {
		json = JSON.parse(evidence);
	} catch {
		throw new Error("Evidence is not JSON");
	}
	const parsed = EvidenceSchema.safeParse(json);
	if (!parsed.success) throw new Error("Evidence needs string fields attestation and keyId");
	try {
		return {
			attestation: fromBase64Url(parsed.data.attestation),
			keyId: fromBase64Url(parsed.data.keyId),
		};
	} catch {
		throw new Error("Evidence fields are not base64");
	}
}

function bytesOf(v: unknown): Uint8Array | undefined {
	return v instanceof Uint8Array ? v : undefined;
}

/** The single OCTET STRING inside the nonce extension: SEQUENCE { [1] { OCTET STRING } } as Apple issues it, or SEQUENCE { OCTET STRING }. */
function nonceFromExtension(value: Uint8Array): Uint8Array | undefined {
	const seq = children(parseOne(value));
	if (seq.length !== 1) return undefined;
	let inner = seq[0];
	if (inner && inner.cls === 2 && inner.constructed) {
		const kids = children(inner);
		if (kids.length !== 1) return undefined;
		inner = kids[0];
	}
	return inner && isUniversal(inner, TAG.OCTET_STRING) ? inner.content : undefined;
}

interface ParsedAuthData {
	rpIdHash: Uint8Array;
	counter: number;
	aaguid: Uint8Array;
	credentialId: Uint8Array;
	cosePoint?: { x: Uint8Array; y: Uint8Array };
	extensions: Map<string | number, unknown>;
}

/** Authenticator data as WebAuthn defines it (rpIdHash, flags, counter, attested credential data, optional extensions). */
function parseAuthData(auth: Uint8Array): ParsedAuthData {
	if (auth.length < 55) throw new Error("authData is too short");
	const flags = auth[32] as number;
	if ((flags & 0x40) === 0) throw new Error("authData has no attested credential data");
	const view = new DataView(auth.buffer, auth.byteOffset, auth.byteLength);
	const credLen = view.getUint16(53, false);
	const credEnd = 55 + credLen;
	if (credEnd > auth.length) throw new Error("credentialId runs past authData");
	const { value, size } = decodeCborPrefix(auth.subarray(credEnd));
	let rest = auth.subarray(credEnd + size);
	let extensions = new Map<string | number, unknown>();
	// WebAuthn says the ED flag (0x80) announces extensions. Apple's own 2026 sample carries an extension map with flags 0x40, so the flag is not trusted either way: bytes after the key must be exactly one map, and the ED flag may not promise a map that is missing.
	if (rest.length > 0) {
		const ext = decodeCborPrefix(rest);
		if (!(ext.value instanceof Map)) throw new Error("authData extensions are not a map");
		extensions = ext.value as Map<string | number, unknown>;
		rest = rest.subarray(ext.size);
	} else if ((flags & 0x80) !== 0) {
		throw new Error("authData promises extensions but has none");
	}
	if (rest.length !== 0) throw new Error("authData has trailing bytes");
	const cose = value instanceof Map ? (value as Map<string | number, unknown>) : undefined;
	const x = bytesOf(cose?.get(-2));
	const y = bytesOf(cose?.get(-3));
	return {
		rpIdHash: auth.subarray(0, 32),
		counter: view.getUint32(33, false),
		aaguid: auth.subarray(37, 53),
		credentialId: auth.subarray(55, credEnd),
		...(x && y && { cosePoint: { x, y } }),
		extensions,
	};
}

/** The uncompressed X9.62 point (0x04 || X || Y) of a P-256 SubjectPublicKeyInfo. */
function p256Point(spki: Uint8Array): Uint8Array | undefined {
	const info = spkiInfo(spki);
	if (info.alg !== "1.2.840.10045.2.1" || info.curve !== "1.2.840.10045.3.1.7") return undefined;
	const [, bits] = children(parseOne(spki));
	const point = bits ? bitStringBytes(bits) : undefined;
	return point && point.length === 65 && point[0] === 4 ? point : undefined;
}

function numberExtension(v: unknown): number | undefined {
	if (typeof v === "number") return v;
	// Apple's 2026 sample stores the category as four little endian bytes.
	if (v instanceof Uint8Array && v.length === 4) {
		return (
			(v[0] as number) +
			(v[1] as number) * 2 ** 8 +
			(v[2] as number) * 2 ** 16 +
			(v[3] as number) * 2 ** 24
		);
	}
	return undefined;
}

function encodeNonce(nonce: string, encoding: "utf8" | "base64url" | "hex"): Uint8Array {
	if (encoding === "utf8") return new TextEncoder().encode(nonce);
	return encoding === "hex" ? fromHex(nonce) : fromBase64Url(nonce);
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
	const out = new Uint8Array(a.length + b.length);
	out.set(a, 0);
	out.set(b, a.length);
	return out;
}

/**
 * Verifier for Apple App Attest attestation objects, for `devices.attestation.verify`.
 *
 * It follows Apple's "Validating apps that connect to your server" and "Attestation Object Validation Guide" step by step: format `apple-appattest`, an `x5c` chain of the credential and intermediate certificates to the Apple App Attestation Root CA, nonce equal to SHA-256 of authData followed by the client data hash (checked against the credential certificate's `1.2.840.113635.100.8.2` extension), key identifier equal to SHA-256 of the certificate's public key point and to the credential id, `rpIdHash` equal to SHA-256 of the App ID, counter zero, and the AAGUID of the expected environment.
 *
 * Sources: https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server and https://developer.apple.com/documentation/devicecheck/attestation-object-validation-guide
 */
export function createAppleAppAttestVerifier(options: AppleAppAttestOptions) {
	const anchors: X509Cert[] = (options.roots ?? APPLE_APP_ATTEST_ROOTS).map((r) =>
		parseCertificate(certBytesFromText(r)),
	);
	const environment = options.environment ?? "production";
	const fail = (reason: string): DeviceAttestationResult => ({ ok: false, reason });

	return async function verify(input: DeviceAttestationInput): Promise<DeviceAttestationResult> {
		if (input.nonce === undefined || input.nonce === "")
			return fail("App Attest needs the enrollment nonce");
		if (options.appIds.length === 0) return fail("No App ID is allowed");
		const bind = options.bind ?? "client-data";
		if (
			bind !== "none" &&
			(input.credentialKind !== "jwk" || input.credentialKeyThumbprint === undefined)
		) {
			return fail("Enroll a jwk credential: the attestation must be bound to the enrolled key");
		}
		let attestation: Uint8Array;
		let keyId: Uint8Array;
		try {
			({ attestation, keyId } = parseAppleAppAttestEvidence(input.evidence));
		} catch (err) {
			return fail(err instanceof Error ? err.message : "Evidence is malformed");
		}

		let fmt: unknown;
		let authData: Uint8Array | undefined;
		let chain: X509Cert[];
		let auth: ParsedAuthData;
		try {
			const obj = decodeCborExact(attestation);
			if (!(obj instanceof Map)) return fail("Attestation object is not a map");
			fmt = obj.get("fmt");
			authData = bytesOf(obj.get("authData"));
			const stmt = obj.get("attStmt");
			const x5c = stmt instanceof Map ? stmt.get("x5c") : undefined;
			if (fmt !== "apple-appattest") return fail("Attestation format is not apple-appattest");
			if (!authData) return fail("Attestation object has no authData");
			if (!Array.isArray(x5c) || x5c.length !== 2) {
				return fail("x5c must hold the credential and the intermediate certificate");
			}
			chain = x5c.map((c) => {
				const der = bytesOf(c);
				if (!der) throw new Error("x5c entry is not a byte string");
				return parseCertificate(der);
			});
			auth = parseAuthData(authData);
		} catch (err) {
			return fail(err instanceof Error ? err.message : "Attestation object is malformed");
		}
		const [cred] = chain as [X509Cert, X509Cert];

		const result = await verifyChain(chain, anchors, { now: options.now?.() ?? new Date() });
		if (!result.ok) return fail(result.reason);

		// Step 3 and 4: nonce = SHA-256(authData || clientDataHash), compared with the certificate extension.
		let nonceBytes: Uint8Array;
		try {
			nonceBytes = encodeNonce(input.nonce, options.challengeEncoding ?? "utf8");
		} catch {
			return fail("Nonce cannot be encoded as the client data");
		}
		const clientData =
			bind === "client-data"
				? concat(nonceBytes, new TextEncoder().encode(`:${input.credentialKeyThumbprint}`))
				: nonceBytes;
		const clientDataHash =
			(options.clientDataHash ?? "sha256") === "raw" ? clientData : await sha256Raw(clientData);
		const expectedNonce = await sha256Raw(concat(authData, clientDataHash));
		const ext = cred.extensions.get(NONCE_OID);
		let certNonce: Uint8Array | undefined;
		try {
			certNonce = ext ? nonceFromExtension(ext.value) : undefined;
		} catch {
			certNonce = undefined;
		}
		if (!certNonce || !constantTimeEqual(certNonce, expectedNonce)) {
			return fail("Attestation nonce does not match the enrollment nonce");
		}

		// Step 5 and 8: key identifier is SHA-256 of the X9.62 point, and equals the credential id.
		const point = p256Point(cred.spki);
		if (!point) return fail("Credential certificate key is not an EC P-256 key");
		const pointHash = await sha256Raw(point);
		if (!constantTimeEqual(pointHash, keyId))
			return fail("Key id is not the hash of the attested key");
		if (!constantTimeEqual(auth.credentialId, keyId)) return fail("credentialId is not the key id");
		if (auth.cosePoint) {
			const { x, y } = auth.cosePoint;
			if (!constantTimeEqual(concat(x, y), point.subarray(1))) {
				return fail("authData key differs from the credential certificate key");
			}
		}

		// Step 6: rpIdHash is SHA-256 of the App ID.
		let appId: string | undefined;
		for (const candidate of options.appIds) {
			if (constantTimeEqual(await sha256Raw(candidate), auth.rpIdHash)) appId = candidate;
		}
		if (!appId) return fail("Attested app is not an allowed App ID");

		// Step 7: counter zero, and the AAGUID of the environment we expect.
		if (auth.counter !== 0) return fail("Attestation counter is not zero");
		const isProd = constantTimeEqual(auth.aaguid, AAGUID_PRODUCTION);
		const isDev = constantTimeEqual(auth.aaguid, AAGUID_DEVELOPMENT);
		if (
			!(isProd || isDev) ||
			(isProd && environment === "development") ||
			(isDev && environment === "production")
		) {
			return fail("Attestation environment is not accepted");
		}

		const category = numberExtension(auth.extensions.get("apple_validation_category_01"));
		if (options.allowedValidationCategories) {
			if (category === undefined || !options.allowedValidationCategories.includes(category)) {
				return fail("Validation category is not accepted");
			}
		}
		const bundleVersion = auth.extensions.get("apple_bundle_version_01");

		const attestedKey = await keyThumbprint(cred.spki);
		if (
			bind === "attested-key" &&
			(attestedKey === undefined || attestedKey !== input.credentialKeyThumbprint)
		) {
			return fail("Attested key is not the enrolled key");
		}

		return {
			ok: true,
			claims: {
				format: "apple-app-attest",
				bound: bind,
				environment: isProd ? "production" : "development",
				appId,
				keyId: btoa(String.fromCharCode(...keyId)),
				...(attestedKey !== undefined && { attestedKeyThumbprint: attestedKey }),
				...(category !== undefined && { validationCategory: category }),
				...(typeof bundleVersion === "string" && { bundleVersion }),
				attestationRootSerial: result.anchor.serialHex,
			},
		};
	};
}
