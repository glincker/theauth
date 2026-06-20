/**
 * Passkey / WebAuthn authentication for TheAuth.
 *
 * Implements server-side WebAuthn (Level 2) without external libraries.
 * Uses the Web Crypto API for signature verification
 * and a minimal CBOR decoder for attestation object parsing.
 *
 * Flow:
 *   Registration
 *     1. getRegistrationOptions(userId, userName) -> send to browser
 *     2. browser calls navigator.credentials.create(options)
 *     3. verifyRegistration(userId, response) -> stores credential
 *
 *   Authentication
 *     1. getAuthenticationOptions(userId?) -> send to browser
 *     2. browser calls navigator.credentials.get(options)
 *     3. verifyAuthentication(response) -> returns userId + credential
 */

import { and, eq, lt } from "drizzle-orm";
import {
	constantTimeEqual,
	fromBase64Url,
	randomBytes,
	toBase64Url,
	toHex,
} from "../crypto/web-crypto.js";
import type { Database } from "../db/database.js";
import { passkeyChallenges, passkeyCredentials } from "../db/schema.js";
import { decodeCbor } from "./cbor.js";

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

export const PASSKEY_ERROR = {
	CHALLENGE_NOT_FOUND: "CHALLENGE_NOT_FOUND",
	CHALLENGE_EXPIRED: "CHALLENGE_EXPIRED",
	CHALLENGE_REPLAY: "CHALLENGE_REPLAY",
	ORIGIN_MISMATCH: "ORIGIN_MISMATCH",
	RPID_MISMATCH: "RPID_MISMATCH",
	CLIENT_DATA_TYPE_MISMATCH: "CLIENT_DATA_TYPE_MISMATCH",
	USER_NOT_PRESENT: "USER_NOT_PRESENT",
	USER_NOT_VERIFIED: "USER_NOT_VERIFIED",
	CREDENTIAL_NOT_FOUND: "CREDENTIAL_NOT_FOUND",
	CREDENTIAL_ALREADY_EXISTS: "CREDENTIAL_ALREADY_EXISTS",
	SIGNATURE_INVALID: "SIGNATURE_INVALID",
	SIGN_COUNT_ROLLBACK: "SIGN_COUNT_ROLLBACK",
	MISSING_ATTESTATION_DATA: "MISSING_ATTESTATION_DATA",
	INVALID_ATTESTATION: "INVALID_ATTESTATION",
	UNSUPPORTED_ALGORITHM: "UNSUPPORTED_ALGORITHM",
	INVALID_COSE_KEY: "INVALID_COSE_KEY",
	INVALID_CLIENT_DATA: "INVALID_CLIENT_DATA",
} as const;

export class PasskeyError extends Error {
	readonly code: string;

	constructor(code: string, message: string) {
		super(message);
		this.name = "PasskeyError";
		this.code = code;
	}
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface PasskeyConfig {
	/** Relying Party name (your app name) */
	rpName: string;
	/** Relying Party ID (your domain, e.g., "example.com") */
	rpId: string;
	/** Expected origin (e.g., "https://example.com") */
	origin: string | string[];
	/** Attestation preference (default: "none") */
	attestation?: "none" | "indirect" | "direct";
	/** User verification requirement (default: "preferred") */
	userVerification?: "required" | "preferred" | "discouraged";
	/** Challenge timeout in ms (default: 60000, max: 300000) */
	challengeTimeout?: number;
}

export interface PasskeyCredential {
	id: string;
	credentialId: string;
	publicKey: string;
	counter: number;
	userId: string;
	deviceName?: string;
	transports?: string[];
	createdAt: Date;
	lastUsedAt: Date;
}

export interface PasskeyModule {
	getRegistrationOptions: (
		userId: string,
		userName: string,
	) => Promise<{
		challenge: string;
		rp: { name: string; id: string };
		user: { id: string; name: string; displayName: string };
		pubKeyCredParams: Array<{ type: "public-key"; alg: number }>;
		timeout: number;
		attestation: string;
		authenticatorSelection: {
			userVerification: string;
			residentKey: string;
			requireResidentKey: boolean;
		};
		excludeCredentials: Array<{ id: string; type: "public-key"; transports?: string[] }>;
	}>;

	verifyRegistration: (
		userId: string,
		response: {
			id: string;
			rawId: string;
			type: "public-key";
			response: {
				clientDataJSON: string;
				attestationObject: string;
			};
			deviceName?: string;
			transports?: string[];
		},
	) => Promise<{ credential: PasskeyCredential }>;

	getAuthenticationOptions: (userId?: string) => Promise<{
		challenge: string;
		rpId: string;
		timeout: number;
		userVerification: string;
		allowCredentials: Array<{ id: string; type: "public-key"; transports?: string[] }>;
	}>;

	verifyAuthentication: (response: {
		id: string;
		rawId: string;
		type: "public-key";
		response: {
			clientDataJSON: string;
			authenticatorData: string;
			signature: string;
		};
	}) => Promise<{ userId: string; credential: PasskeyCredential }>;

	listCredentials: (userId: string) => Promise<PasskeyCredential[]>;
	removeCredential: (credentialId: string, userId: string) => Promise<void>;
	handleRequest: (request: Request) => Promise<Response | null>;
}

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

interface CoseKey {
	kty: number;
	alg: number;
	crv?: number;
	x?: Uint8Array;
	y?: Uint8Array;
	/** RSA modulus (COSE map key -1 for kty=3) */
	n?: Uint8Array;
	/** RSA exponent (COSE map key -2 for kty=3) */
	e?: Uint8Array;
}

// COSE key type constants (OKP=1, EC2=2 used implicitly by algorithm detection)
const COSE_KTY_RSA = 3;

// COSE algorithm constants
const COSE_ALG_ES256 = -7;
const COSE_ALG_ES384 = -35;
const COSE_ALG_ES512 = -36;
const COSE_ALG_RS256 = -257;
const COSE_ALG_EDDSA = -8;

/** Maximum challenge timeout: 5 minutes */
const MAX_CHALLENGE_TIMEOUT = 300_000;

/** Default challenge timeout: 60 seconds */
const DEFAULT_CHALLENGE_TIMEOUT = 60_000;

// ---------------------------------------------------------------------------
// Base64url helpers (no Buffer -- uses btoa/atob via Uint8Array)
// ---------------------------------------------------------------------------

// toBase64Url and fromBase64Url are imported from ../crypto/web-crypto.js

// ---------------------------------------------------------------------------
// Crypto helpers
// ---------------------------------------------------------------------------

async function sha256(data: Uint8Array): Promise<Uint8Array> {
	const buf = (data.buffer as ArrayBuffer).slice(
		data.byteOffset,
		data.byteOffset + data.byteLength,
	);
	const hash = await globalThis.crypto.subtle.digest("SHA-256", buf);
	return new Uint8Array(hash);
}

/**
 * Constant-time byte comparison using Web Crypto constantTimeEqual.
 * Prevents timing side-channel attacks on hash comparisons.
 */
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
	if (a.length !== b.length) return false;
	return constantTimeEqual(a, b);
}

// ---------------------------------------------------------------------------
// COSE key parsing and verification
// ---------------------------------------------------------------------------

function parseCoseKey(coseMap: Map<unknown, unknown>): CoseKey {
	const kty = coseMap.get(1) as number;
	const alg = coseMap.get(3) as number;

	if (typeof kty !== "number" || typeof alg !== "number") {
		throw new PasskeyError(
			PASSKEY_ERROR.INVALID_COSE_KEY,
			"COSE key missing required kty or alg fields",
		);
	}

	if (kty === COSE_KTY_RSA) {
		// RSA: n is at map key -1, e is at map key -2
		const n = coseMap.get(-1) as Uint8Array | undefined;
		const e = coseMap.get(-2) as Uint8Array | undefined;
		return { kty, alg, n, e };
	}

	// EC2 or OKP
	const crv = coseMap.get(-1) as number | undefined;
	const x = coseMap.get(-2) as Uint8Array | undefined;
	const y = coseMap.get(-3) as Uint8Array | undefined;
	return { kty, alg, crv, x, y };
}

/**
 * Returns the expected coordinate size in bytes for a given COSE EC algorithm.
 */
function ecCoordSize(alg: number): number {
	switch (alg) {
		case COSE_ALG_ES256:
			return 32;
		case COSE_ALG_ES384:
			return 48;
		case COSE_ALG_ES512:
			return 66;
		default:
			return 32;
	}
}

async function verifySignatureES(
	coseKey: CoseKey,
	data: Uint8Array,
	signature: Uint8Array,
	namedCurve: string,
	hash: string,
): Promise<boolean> {
	if (!coseKey.x || !coseKey.y) {
		throw new PasskeyError(PASSKEY_ERROR.INVALID_COSE_KEY, "Missing EC key coordinates");
	}

	const jwk = {
		kty: "EC",
		crv: namedCurve,
		x: toBase64Url(coseKey.x),
		y: toBase64Url(coseKey.y),
	};

	const key = await globalThis.crypto.subtle.importKey(
		"jwk",
		jwk,
		{ name: "ECDSA", namedCurve },
		false,
		["verify"],
	);

	// WebAuthn signatures use DER-encoded ECDSA; Web Crypto expects raw (r||s)
	const rawSig = derToRaw(signature, ecCoordSize(coseKey.alg));

	const sigBuf = (rawSig.buffer as ArrayBuffer).slice(
		rawSig.byteOffset,
		rawSig.byteOffset + rawSig.byteLength,
	);
	const dataBuf = (data.buffer as ArrayBuffer).slice(
		data.byteOffset,
		data.byteOffset + data.byteLength,
	);
	return globalThis.crypto.subtle.verify(
		{ name: "ECDSA", hash: { name: hash } },
		key,
		sigBuf,
		dataBuf,
	);
}

/**
 * Convert DER-encoded ECDSA signature to raw (r||s) format.
 * DER format: 0x30 len 0x02 rLen r 0x02 sLen s
 *
 * @param coordSize - Expected coordinate size in bytes (32 for P-256, 48 for P-384, 66 for P-521)
 */
function derToRaw(der: Uint8Array, coordSize: number): Uint8Array {
	if (der[0] !== 0x30) return der; // not DER, assume already raw
	let offset = 2; // skip 0x30 and total length
	if (der[1] === 0x81) offset = 3; // long form length

	// Read r
	if (der[offset] !== 0x02) {
		throw new PasskeyError(PASSKEY_ERROR.SIGNATURE_INVALID, "Invalid DER: expected 0x02 for r");
	}
	offset++;
	const rLen = der[offset] ?? 0;
	offset++;
	const rBytes = der.slice(offset, offset + rLen);
	offset += rLen;

	// Read s
	if (der[offset] !== 0x02) {
		throw new PasskeyError(PASSKEY_ERROR.SIGNATURE_INVALID, "Invalid DER: expected 0x02 for s");
	}
	offset++;
	const sLen = der[offset] ?? 0;
	offset++;
	const sBytes = der.slice(offset, offset + sLen);

	// Strip leading zero padding (DER uses it to signal positive integers)
	const r = rBytes[0] === 0 ? rBytes.slice(1) : rBytes;
	const s = sBytes[0] === 0 ? sBytes.slice(1) : sBytes;

	// Pad to correct coordinate size
	const raw = new Uint8Array(coordSize * 2);
	raw.set(r, coordSize - r.length);
	raw.set(s, coordSize * 2 - s.length);
	return raw;
}

async function verifySignatureRSA(
	coseKey: CoseKey,
	data: Uint8Array,
	signature: Uint8Array,
): Promise<boolean> {
	if (!coseKey.n || !coseKey.e) {
		throw new PasskeyError(PASSKEY_ERROR.INVALID_COSE_KEY, "Missing RSA key modulus or exponent");
	}

	const jwk = {
		kty: "RSA",
		n: toBase64Url(coseKey.n),
		e: toBase64Url(coseKey.e),
		alg: "RS256",
	};

	const key = await globalThis.crypto.subtle.importKey(
		"jwk",
		jwk,
		{ name: "RSASSA-PKCS1-v1_5", hash: { name: "SHA-256" } },
		false,
		["verify"],
	);

	const sigBuf = (signature.buffer as ArrayBuffer).slice(
		signature.byteOffset,
		signature.byteOffset + signature.byteLength,
	);
	const dataBuf = (data.buffer as ArrayBuffer).slice(
		data.byteOffset,
		data.byteOffset + data.byteLength,
	);
	return globalThis.crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, sigBuf, dataBuf);
}

async function verifySignatureEdDSA(
	coseKey: CoseKey,
	data: Uint8Array,
	signature: Uint8Array,
): Promise<boolean> {
	if (!coseKey.x) {
		throw new PasskeyError(PASSKEY_ERROR.INVALID_COSE_KEY, "Missing EdDSA public key x");
	}

	const jwk = {
		kty: "OKP",
		crv: "Ed25519",
		x: toBase64Url(coseKey.x),
	};

	const key = await globalThis.crypto.subtle.importKey("jwk", jwk, { name: "Ed25519" }, false, [
		"verify",
	]);

	const sigBuf = (signature.buffer as ArrayBuffer).slice(
		signature.byteOffset,
		signature.byteOffset + signature.byteLength,
	);
	const dataBuf = (data.buffer as ArrayBuffer).slice(
		data.byteOffset,
		data.byteOffset + data.byteLength,
	);
	return globalThis.crypto.subtle.verify({ name: "Ed25519" }, key, sigBuf, dataBuf);
}

async function verifyCoseSignature(
	publicKeyCbor: Uint8Array,
	data: Uint8Array,
	signature: Uint8Array,
): Promise<boolean> {
	const decoded = decodeCbor(publicKeyCbor);
	if (!(decoded instanceof Map)) {
		throw new PasskeyError(PASSKEY_ERROR.INVALID_COSE_KEY, "COSE key is not a CBOR map");
	}

	const coseKey = parseCoseKey(decoded);

	switch (coseKey.alg) {
		case COSE_ALG_ES256:
			return verifySignatureES(coseKey, data, signature, "P-256", "SHA-256");
		case COSE_ALG_ES384:
			return verifySignatureES(coseKey, data, signature, "P-384", "SHA-384");
		case COSE_ALG_ES512:
			return verifySignatureES(coseKey, data, signature, "P-521", "SHA-512");
		case COSE_ALG_RS256:
			return verifySignatureRSA(coseKey, data, signature);
		case COSE_ALG_EDDSA:
			return verifySignatureEdDSA(coseKey, data, signature);
		default:
			throw new PasskeyError(
				PASSKEY_ERROR.UNSUPPORTED_ALGORITHM,
				`Unsupported COSE algorithm: ${coseKey.alg}`,
			);
	}
}

// ---------------------------------------------------------------------------
// AuthData parsing
// ---------------------------------------------------------------------------

interface ParsedAuthData {
	rpIdHash: Uint8Array;
	flags: number;
	signCount: number;
	attestedCredentialData?: {
		aaguid: Uint8Array;
		credentialId: Uint8Array;
		credentialPublicKey: Uint8Array;
		credentialPublicKeyOffset: number;
	};
}

const FLAG_UP = 0x01; // user present
const FLAG_UV = 0x04; // user verified
const FLAG_AT = 0x40; // attested credential data included

function parseAuthData(authData: Uint8Array): ParsedAuthData {
	if (authData.length < 37) {
		throw new PasskeyError(PASSKEY_ERROR.INVALID_ATTESTATION, "authData too short");
	}

	const rpIdHash = authData.slice(0, 32);
	const flags = authData[32] ?? 0;
	const signCount =
		(((authData[33] ?? 0) << 24) |
			((authData[34] ?? 0) << 16) |
			((authData[35] ?? 0) << 8) |
			(authData[36] ?? 0)) >>>
		0;

	let attestedCredentialData: ParsedAuthData["attestedCredentialData"];

	if (flags & FLAG_AT) {
		if (authData.length < 55) {
			throw new PasskeyError(
				PASSKEY_ERROR.INVALID_ATTESTATION,
				"authData too short for attested credential data",
			);
		}

		const aaguid = authData.slice(37, 53);
		const credentialIdLength = ((authData[53] ?? 0) << 8) | (authData[54] ?? 0);

		if (authData.length < 55 + credentialIdLength) {
			throw new PasskeyError(
				PASSKEY_ERROR.INVALID_ATTESTATION,
				"authData too short for credential ID",
			);
		}

		const credentialId = authData.slice(55, 55 + credentialIdLength);
		const credentialPublicKeyOffset = 55 + credentialIdLength;
		const credentialPublicKey = authData.slice(credentialPublicKeyOffset);

		attestedCredentialData = {
			aaguid,
			credentialId,
			credentialPublicKey,
			credentialPublicKeyOffset,
		};
	}

	return { rpIdHash, flags, signCount, attestedCredentialData };
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

function jsonResponse(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "Content-Type": "application/json" },
	});
}

async function parseBody(request: Request): Promise<Record<string, unknown>> {
	try {
		return (await request.json()) as Record<string, unknown>;
	} catch {
		return {};
	}
}

function getPathSegments(url: URL): string[] {
	return url.pathname.split("/").filter(Boolean);
}

// ---------------------------------------------------------------------------
// Origin validation
// ---------------------------------------------------------------------------

function isOriginAllowed(origin: string, allowed: string | string[]): boolean {
	const origins = Array.isArray(allowed) ? allowed : [allowed];
	return origins.includes(origin);
}

// ---------------------------------------------------------------------------
// Module factory
// ---------------------------------------------------------------------------

export function createPasskeyModule(config: PasskeyConfig, db: Database): PasskeyModule {
	const timeout = Math.min(
		config.challengeTimeout ?? DEFAULT_CHALLENGE_TIMEOUT,
		MAX_CHALLENGE_TIMEOUT,
	);
	const userVerification = config.userVerification ?? "preferred";
	const attestation = config.attestation ?? "none";

	// ── getRegistrationOptions ───────────────────────────────────────────────

	async function getRegistrationOptions(
		userId: string,
		userName: string,
	): ReturnType<PasskeyModule["getRegistrationOptions"]> {
		// Clean up expired challenges
		await db.delete(passkeyChallenges).where(lt(passkeyChallenges.expiresAt, new Date()));

		const challengeBytes = randomBytes(32);
		const challenge = toBase64Url(challengeBytes);
		const id = toHex(randomBytes(16));
		const now = new Date();
		const expiresAt = new Date(now.getTime() + timeout);

		await db.insert(passkeyChallenges).values({
			id,
			challenge,
			userId,
			type: "registration",
			expiresAt,
			createdAt: now,
		});

		// Get existing credentials to exclude
		const existing = await db
			.select()
			.from(passkeyCredentials)
			.where(eq(passkeyCredentials.userId, userId));

		const excludeCredentials = existing.map((c) => ({
			id: c.credentialId,
			type: "public-key" as const,
			transports: c.transports ? (JSON.parse(c.transports as string) as string[]) : undefined,
		}));

		return {
			challenge,
			rp: { name: config.rpName, id: config.rpId },
			user: { id: userId, name: userName, displayName: userName },
			pubKeyCredParams: [
				{ type: "public-key", alg: COSE_ALG_ES256 },
				{ type: "public-key", alg: COSE_ALG_RS256 },
				{ type: "public-key", alg: COSE_ALG_EDDSA },
			],
			timeout,
			attestation,
			authenticatorSelection: {
				userVerification,
				residentKey: "preferred",
				requireResidentKey: false,
			},
			excludeCredentials,
		};
	}

	// ── verifyRegistration ───────────────────────────────────────────────────

	async function verifyRegistration(
		userId: string,
		response: Parameters<PasskeyModule["verifyRegistration"]>[1],
	): ReturnType<PasskeyModule["verifyRegistration"]> {
		// 1. Decode clientDataJSON
		const clientDataBytes = fromBase64Url(response.response.clientDataJSON);
		let clientData: { type: string; challenge: string; origin: string; crossOrigin?: boolean };
		try {
			clientData = JSON.parse(new TextDecoder().decode(clientDataBytes)) as {
				type: string;
				challenge: string;
				origin: string;
				crossOrigin?: boolean;
			};
		} catch {
			throw new PasskeyError(PASSKEY_ERROR.INVALID_CLIENT_DATA, "Failed to parse clientDataJSON");
		}

		// 1a. Reject cross-origin iframes explicitly
		if (clientData.crossOrigin === true) {
			throw new PasskeyError(
				PASSKEY_ERROR.ORIGIN_MISMATCH,
				"Cross-origin WebAuthn requests are not allowed",
			);
		}

		if (clientData.type !== "webauthn.create") {
			throw new PasskeyError(
				PASSKEY_ERROR.CLIENT_DATA_TYPE_MISMATCH,
				`Expected type "webauthn.create", got "${clientData.type}"`,
			);
		}
		if (!isOriginAllowed(clientData.origin, config.origin)) {
			throw new PasskeyError(
				PASSKEY_ERROR.ORIGIN_MISMATCH,
				`Origin mismatch: got "${clientData.origin}"`,
			);
		}

		// 2. Verify challenge
		const challengeRows = await db
			.select()
			.from(passkeyChallenges)
			.where(
				and(
					eq(passkeyChallenges.challenge, clientData.challenge),
					eq(passkeyChallenges.userId, userId),
					eq(passkeyChallenges.type, "registration"),
				),
			);

		const challengeRow = challengeRows[0];
		if (!challengeRow) {
			throw new PasskeyError(
				PASSKEY_ERROR.CHALLENGE_NOT_FOUND,
				"Challenge not found or already used",
			);
		}

		// Delete the challenge FIRST (one-time use, prevent replay even if later steps fail)
		await db.delete(passkeyChallenges).where(eq(passkeyChallenges.id, challengeRow.id));

		if (challengeRow.expiresAt < new Date()) {
			throw new PasskeyError(PASSKEY_ERROR.CHALLENGE_EXPIRED, "Challenge expired");
		}

		// 3. Decode attestationObject (CBOR)
		const attestationBytes = fromBase64Url(response.response.attestationObject);
		const attestationObj = decodeCbor(attestationBytes);
		if (!(attestationObj instanceof Map)) {
			throw new PasskeyError(PASSKEY_ERROR.INVALID_ATTESTATION, "Invalid attestation object");
		}

		const authDataRaw = attestationObj.get("authData") as Uint8Array;
		if (!authDataRaw || !(authDataRaw instanceof Uint8Array)) {
			throw new PasskeyError(
				PASSKEY_ERROR.INVALID_ATTESTATION,
				"Missing authData in attestation object",
			);
		}

		// 4. Parse authData
		const authData = parseAuthData(authDataRaw);

		// 5. Verify rpIdHash
		const expectedRpIdHash = new Uint8Array(
			await globalThis.crypto.subtle.digest("SHA-256", new TextEncoder().encode(config.rpId)),
		);
		if (!bytesEqual(authData.rpIdHash, expectedRpIdHash)) {
			throw new PasskeyError(PASSKEY_ERROR.RPID_MISMATCH, "rpIdHash mismatch");
		}

		// 6. Verify user present flag
		if (!(authData.flags & FLAG_UP)) {
			throw new PasskeyError(PASSKEY_ERROR.USER_NOT_PRESENT, "User present flag not set");
		}

		// 6a. Verify user verified flag when required
		if (userVerification === "required" && !(authData.flags & FLAG_UV)) {
			throw new PasskeyError(
				PASSKEY_ERROR.USER_NOT_VERIFIED,
				"User verified flag not set but required",
			);
		}

		// 7. Extract credential data
		if (!authData.attestedCredentialData) {
			throw new PasskeyError(
				PASSKEY_ERROR.MISSING_ATTESTATION_DATA,
				"No attested credential data in authData",
			);
		}

		const { credentialId, credentialPublicKey } = authData.attestedCredentialData;
		const credentialIdB64 = toBase64Url(credentialId);
		const publicKeyB64 = toBase64Url(credentialPublicKey);

		// 8. Check for duplicate credential ID
		const existing = await db
			.select()
			.from(passkeyCredentials)
			.where(eq(passkeyCredentials.credentialId, credentialIdB64));

		if (existing.length > 0) {
			throw new PasskeyError(
				PASSKEY_ERROR.CREDENTIAL_ALREADY_EXISTS,
				"Credential already registered",
			);
		}

		// 9. Store credential
		const now = new Date();
		const id = toHex(randomBytes(16));

		const transports = response.transports ? JSON.stringify(response.transports) : null;

		await db.insert(passkeyCredentials).values({
			id,
			userId,
			credentialId: credentialIdB64,
			publicKey: publicKeyB64,
			counter: authData.signCount,
			deviceName: response.deviceName ?? null,
			transports,
			createdAt: now,
			lastUsedAt: now,
		});

		const credential: PasskeyCredential = {
			id,
			credentialId: credentialIdB64,
			publicKey: publicKeyB64,
			counter: authData.signCount,
			userId,
			deviceName: response.deviceName,
			transports: response.transports,
			createdAt: now,
			lastUsedAt: now,
		};

		return { credential };
	}

	// ── getAuthenticationOptions ─────────────────────────────────────────────

	async function getAuthenticationOptions(
		userId?: string,
	): ReturnType<PasskeyModule["getAuthenticationOptions"]> {
		await db.delete(passkeyChallenges).where(lt(passkeyChallenges.expiresAt, new Date()));

		const challengeBytes = randomBytes(32);
		const challenge = toBase64Url(challengeBytes);
		const id = toHex(randomBytes(16));
		const now = new Date();
		const expiresAt = new Date(now.getTime() + timeout);

		await db.insert(passkeyChallenges).values({
			id,
			challenge,
			userId: userId ?? null,
			type: "authentication",
			expiresAt,
			createdAt: now,
		});

		let allowCredentials: Array<{ id: string; type: "public-key"; transports?: string[] }> = [];

		if (userId) {
			const creds = await db
				.select()
				.from(passkeyCredentials)
				.where(eq(passkeyCredentials.userId, userId));

			allowCredentials = creds.map((c) => ({
				id: c.credentialId,
				type: "public-key" as const,
				transports: c.transports ? (JSON.parse(c.transports as string) as string[]) : undefined,
			}));
		}

		return {
			challenge,
			rpId: config.rpId,
			timeout,
			userVerification,
			allowCredentials,
		};
	}

	// ── verifyAuthentication ─────────────────────────────────────────────────

	async function verifyAuthentication(
		response: Parameters<PasskeyModule["verifyAuthentication"]>[0],
	): ReturnType<PasskeyModule["verifyAuthentication"]> {
		// 1. Decode clientDataJSON
		const clientDataBytes = fromBase64Url(response.response.clientDataJSON);
		let clientData: { type: string; challenge: string; origin: string; crossOrigin?: boolean };
		try {
			clientData = JSON.parse(new TextDecoder().decode(clientDataBytes)) as {
				type: string;
				challenge: string;
				origin: string;
				crossOrigin?: boolean;
			};
		} catch {
			throw new PasskeyError(PASSKEY_ERROR.INVALID_CLIENT_DATA, "Failed to parse clientDataJSON");
		}

		// 1a. Reject cross-origin iframes
		if (clientData.crossOrigin === true) {
			throw new PasskeyError(
				PASSKEY_ERROR.ORIGIN_MISMATCH,
				"Cross-origin WebAuthn requests are not allowed",
			);
		}

		if (clientData.type !== "webauthn.get") {
			throw new PasskeyError(
				PASSKEY_ERROR.CLIENT_DATA_TYPE_MISMATCH,
				`Expected type "webauthn.get", got "${clientData.type}"`,
			);
		}
		if (!isOriginAllowed(clientData.origin, config.origin)) {
			throw new PasskeyError(
				PASSKEY_ERROR.ORIGIN_MISMATCH,
				`Origin mismatch: got "${clientData.origin}"`,
			);
		}

		// 2. Verify challenge
		const challengeRows = await db
			.select()
			.from(passkeyChallenges)
			.where(
				and(
					eq(passkeyChallenges.challenge, clientData.challenge),
					eq(passkeyChallenges.type, "authentication"),
				),
			);

		const challengeRow = challengeRows[0];
		if (!challengeRow) {
			throw new PasskeyError(
				PASSKEY_ERROR.CHALLENGE_NOT_FOUND,
				"Challenge not found or already used",
			);
		}

		// Delete the challenge FIRST (one-time use, prevent replay even if later steps fail)
		await db.delete(passkeyChallenges).where(eq(passkeyChallenges.id, challengeRow.id));

		if (challengeRow.expiresAt < new Date()) {
			throw new PasskeyError(PASSKEY_ERROR.CHALLENGE_EXPIRED, "Challenge expired");
		}

		// 3. Look up credential
		const credentialId = response.id;
		const credRows = await db
			.select()
			.from(passkeyCredentials)
			.where(eq(passkeyCredentials.credentialId, credentialId));

		const credRow = credRows[0];
		if (!credRow) {
			throw new PasskeyError(PASSKEY_ERROR.CREDENTIAL_NOT_FOUND, "Credential not found");
		}

		// 4. Parse authenticatorData
		const authDataBytes = fromBase64Url(response.response.authenticatorData);
		const authData = parseAuthData(authDataBytes);

		// 5. Verify rpIdHash
		const expectedRpIdHash = new Uint8Array(
			await globalThis.crypto.subtle.digest("SHA-256", new TextEncoder().encode(config.rpId)),
		);
		if (!bytesEqual(authData.rpIdHash, expectedRpIdHash)) {
			throw new PasskeyError(PASSKEY_ERROR.RPID_MISMATCH, "rpIdHash mismatch");
		}

		// 6. Verify user present flag
		if (!(authData.flags & FLAG_UP)) {
			throw new PasskeyError(PASSKEY_ERROR.USER_NOT_PRESENT, "User present flag not set");
		}

		// 6a. Verify user verified flag when required
		if (userVerification === "required" && !(authData.flags & FLAG_UV)) {
			throw new PasskeyError(
				PASSKEY_ERROR.USER_NOT_VERIFIED,
				"User verified flag not set but required",
			);
		}

		// 7. Verify signature
		// Data to verify: authData || SHA-256(clientDataJSON)
		const clientDataHash = await sha256(clientDataBytes);
		const signedData = new Uint8Array(authDataBytes.length + clientDataHash.length);
		signedData.set(authDataBytes, 0);
		signedData.set(clientDataHash, authDataBytes.length);

		const signature = fromBase64Url(response.response.signature);
		const publicKeyBytes = fromBase64Url(credRow.publicKey);

		let valid: boolean;
		try {
			valid = await verifyCoseSignature(publicKeyBytes, signedData, signature);
		} catch (err) {
			if (err instanceof PasskeyError) throw err;
			throw new PasskeyError(PASSKEY_ERROR.SIGNATURE_INVALID, "Signature verification failed");
		}

		if (!valid) {
			throw new PasskeyError(PASSKEY_ERROR.SIGNATURE_INVALID, "Signature verification failed");
		}

		// 8. Check counter (clone detection)
		// If both the stored counter and the new counter are 0, the authenticator
		// does not support counters and we skip the check.
		if (credRow.counter > 0 && authData.signCount <= credRow.counter) {
			throw new PasskeyError(
				PASSKEY_ERROR.SIGN_COUNT_ROLLBACK,
				`Sign count rollback detected: stored=${credRow.counter}, received=${authData.signCount}`,
			);
		}

		// 9. Update counter and lastUsedAt
		const now = new Date();
		await db
			.update(passkeyCredentials)
			.set({ counter: authData.signCount, lastUsedAt: now })
			.where(eq(passkeyCredentials.id, credRow.id));

		const credential: PasskeyCredential = {
			id: credRow.id,
			credentialId: credRow.credentialId,
			publicKey: credRow.publicKey,
			counter: authData.signCount,
			userId: credRow.userId,
			deviceName: credRow.deviceName ?? undefined,
			transports: credRow.transports
				? (JSON.parse(credRow.transports as string) as string[])
				: undefined,
			createdAt: credRow.createdAt,
			lastUsedAt: now,
		};

		return { userId: credRow.userId, credential };
	}

	// ── listCredentials ──────────────────────────────────────────────────────

	async function listCredentials(userId: string): Promise<PasskeyCredential[]> {
		const rows = await db
			.select()
			.from(passkeyCredentials)
			.where(eq(passkeyCredentials.userId, userId));

		return rows.map((r) => ({
			id: r.id,
			credentialId: r.credentialId,
			publicKey: r.publicKey,
			counter: r.counter,
			userId: r.userId,
			deviceName: r.deviceName ?? undefined,
			transports: r.transports ? (JSON.parse(r.transports as string) as string[]) : undefined,
			createdAt: r.createdAt,
			lastUsedAt: r.lastUsedAt,
		}));
	}

	// ── removeCredential ─────────────────────────────────────────────────────

	async function removeCredential(credentialId: string, userId: string): Promise<void> {
		await db
			.delete(passkeyCredentials)
			.where(
				and(
					eq(passkeyCredentials.credentialId, credentialId),
					eq(passkeyCredentials.userId, userId),
				),
			);
	}

	// ── handleRequest ────────────────────────────────────────────────────────

	async function handleRequest(request: Request): Promise<Response | null> {
		const url = new URL(request.url);
		const method = request.method.toUpperCase();
		const segments = getPathSegments(url);

		// POST /auth/passkey/register/options
		if (
			method === "POST" &&
			segments.length === 4 &&
			segments[1] === "passkey" &&
			segments[2] === "register" &&
			segments[3] === "options"
		) {
			const body = await parseBody(request);
			const userId = typeof body.userId === "string" ? body.userId : null;
			const userName = typeof body.userName === "string" ? body.userName : null;
			if (!userId || !userName) {
				return jsonResponse({ error: "userId and userName required" }, 400);
			}
			try {
				const options = await getRegistrationOptions(userId, userName);
				return jsonResponse(options);
			} catch (err) {
				const message = err instanceof Error ? err.message : "Failed to generate options";
				const code = err instanceof PasskeyError ? err.code : "INTERNAL_ERROR";
				return jsonResponse({ error: message, code }, 500);
			}
		}

		// POST /auth/passkey/register/verify
		if (
			method === "POST" &&
			segments.length === 4 &&
			segments[1] === "passkey" &&
			segments[2] === "register" &&
			segments[3] === "verify"
		) {
			const body = await parseBody(request);
			const userId = typeof body.userId === "string" ? body.userId : null;
			if (!userId) return jsonResponse({ error: "userId required" }, 400);

			const resp = body.response as Parameters<PasskeyModule["verifyRegistration"]>[1] | undefined;
			if (!resp) return jsonResponse({ error: "response required" }, 400);

			try {
				const result = await verifyRegistration(userId, resp);
				return jsonResponse(result);
			} catch (err) {
				const message = err instanceof Error ? err.message : "Registration failed";
				const code = err instanceof PasskeyError ? err.code : "INTERNAL_ERROR";
				return jsonResponse({ error: message, code }, 400);
			}
		}

		// POST /auth/passkey/login/options
		if (
			method === "POST" &&
			segments.length === 4 &&
			segments[1] === "passkey" &&
			segments[2] === "login" &&
			segments[3] === "options"
		) {
			const body = await parseBody(request);
			const userId = typeof body.userId === "string" ? body.userId : undefined;
			try {
				const options = await getAuthenticationOptions(userId);
				return jsonResponse(options);
			} catch (err) {
				const message = err instanceof Error ? err.message : "Failed to generate options";
				const code = err instanceof PasskeyError ? err.code : "INTERNAL_ERROR";
				return jsonResponse({ error: message, code }, 500);
			}
		}

		// POST /auth/passkey/login/verify
		if (
			method === "POST" &&
			segments.length === 4 &&
			segments[1] === "passkey" &&
			segments[2] === "login" &&
			segments[3] === "verify"
		) {
			const body = await parseBody(request);
			const resp = body.response as
				| Parameters<PasskeyModule["verifyAuthentication"]>[0]
				| undefined;
			if (!resp) return jsonResponse({ error: "response required" }, 400);

			try {
				const result = await verifyAuthentication(resp);
				return jsonResponse(result);
			} catch (err) {
				const message = err instanceof Error ? err.message : "Authentication failed";
				const code = err instanceof PasskeyError ? err.code : "INTERNAL_ERROR";
				return jsonResponse({ error: message, code }, 401);
			}
		}

		// GET /auth/passkey/credentials
		if (
			method === "GET" &&
			segments.length === 3 &&
			segments[1] === "passkey" &&
			segments[2] === "credentials"
		) {
			const userId = url.searchParams.get("userId");
			if (!userId) return jsonResponse({ error: "userId query param required" }, 400);

			try {
				const creds = await listCredentials(userId);
				return jsonResponse({ credentials: creds });
			} catch (err) {
				const message = err instanceof Error ? err.message : "Failed to list credentials";
				return jsonResponse({ error: message }, 500);
			}
		}

		// DELETE /auth/passkey/credentials/:id
		if (
			method === "DELETE" &&
			segments.length === 4 &&
			segments[1] === "passkey" &&
			segments[2] === "credentials"
		) {
			const credentialId = segments[3];
			if (!credentialId) return jsonResponse({ error: "Credential ID required" }, 400);

			const body = await parseBody(request);
			const userId = typeof body.userId === "string" ? body.userId : null;
			if (!userId) return jsonResponse({ error: "userId required" }, 400);

			try {
				await removeCredential(credentialId, userId);
				return jsonResponse({ removed: true });
			} catch (err) {
				const message = err instanceof Error ? err.message : "Failed to remove credential";
				return jsonResponse({ error: message }, 500);
			}
		}

		return null;
	}

	return {
		getRegistrationOptions,
		verifyRegistration,
		getAuthenticationOptions,
		verifyAuthentication,
		listCredentials,
		removeCredential,
		handleRequest,
	};
}
